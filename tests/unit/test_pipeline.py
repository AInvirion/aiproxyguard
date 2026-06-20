# Copyright 2025-2026 AInvirion LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the shared request pipeline."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from aiproxyguard.pipeline import (
    CACHE_STATUS_HEADER,
    PipelineRequest,
    PipelineResult,
    RequestPipeline,
    UpstreamTarget,
)
from aiproxyguard.cache import CachedResponse, is_cacheable


@dataclass
class MockSecurityConfig:
    failure_mode: str = "open"
    scanner_timeout_ms: int = 1000
    upstream_timeout_s: int = 60
    max_request_size: int = 10 * 1024 * 1024
    max_response_size: int = 50 * 1024 * 1024
    expose_details: bool = False


@dataclass
class MockScannerConfig:
    enabled: bool = True
    request_scanning: bool = True


@dataclass
class MockRoutingConfig:
    tasks: dict = field(default_factory=dict)
    downgrades: list = field(default_factory=list)
    dry_run: bool = True


@dataclass
class MockPolicyConfig:
    categories: dict = field(default_factory=dict)


@dataclass
class MockCostOptimizationConfig:
    anthropic_prompt_cache: bool = False
    # Default the response-cache opt-in ON so the cache integration tests below
    # exercise the cache; the opt-out path is covered explicitly.
    response_cache: bool = True


@dataclass
class MockSignaturesConfig:
    # Empty path -> get_signature_version returns None (no bundled signatures),
    # which keeps register_control_plane_callbacks happy in integration tests.
    path: str = ""


@dataclass
class MockConfig:
    security: MockSecurityConfig = field(default_factory=MockSecurityConfig)
    scanner: MockScannerConfig = field(default_factory=MockScannerConfig)
    routing: MockRoutingConfig = field(default_factory=MockRoutingConfig)
    policy: MockPolicyConfig = field(default_factory=MockPolicyConfig)
    cost_optimization: MockCostOptimizationConfig = field(
        default_factory=MockCostOptimizationConfig
    )
    signatures: MockSignaturesConfig = field(default_factory=MockSignaturesConfig)


def make_scan_result(action: str = "allow") -> SimpleNamespace:
    return SimpleNamespace(
        action=action,
        category="prompt-injection" if action != "allow" else None,
        signature_id="sig-001" if action != "allow" else None,
        confidence=0.9,
        details={},
    )


class FakeResponse:
    """Minimal stand-in for an aiohttp client response."""

    def __init__(self, status: int = 200, body: bytes = b'{"ok": true}') -> None:
        self.status = status
        self.reason = "OK"
        self._body = body
        self.content_length = len(body)
        self.headers = {"content-type": "application/json"}

    async def read(self) -> bytes:
        return self._body

    async def __aenter__(self) -> "FakeResponse":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


class FakeSession:
    """Captures the exact bytes and headers sent upstream."""

    def __init__(self, response: FakeResponse | None = None) -> None:
        self.response = response or FakeResponse()
        self.calls: list[dict] = []

    def request(self, **kwargs: object) -> FakeResponse:
        self.calls.append(kwargs)
        return self.response


def make_pipeline(
    config: MockConfig | None = None,
    scan_action: str = "allow",
    policy_action: str | None = None,
    session: FakeSession | None = None,
) -> tuple[RequestPipeline, FakeSession]:
    config = config or MockConfig()
    session = session or FakeSession()

    scanner = MagicMock()
    scanner.scan_async = AsyncMock(return_value=make_scan_result(scan_action))
    scanner.response_scanner = None

    policy = MagicMock()
    policy.resolve.return_value = policy_action or scan_action
    policy.categories = {}  # live policy categories (drives the cache PII/PHI gate)

    pipeline = RequestPipeline(
        config=config,
        scanner=scanner,
        policy=policy,
        metrics=MagicMock(),
        session_getter=lambda: session,
    )
    return pipeline, session


def make_request(body: bytes, headers: dict[str, str] | None = None) -> PipelineRequest:
    return PipelineRequest(
        method="POST",
        path="/openai/v1/chat/completions",
        headers=headers or {"content-type": "application/json"},
        body=body,
        client_id="client-1",
        target=UpstreamTarget(
            provider="openai",
            url="https://api.openai.com/v1/chat/completions",
            auth_header="Authorization",
            timeout=30.0,
        ),
    )


class TestPassthrough:
    """Without mutators, the original raw bytes must be forwarded untouched."""

    async def test_raw_bytes_forwarded_unchanged(self) -> None:
        pipeline, session = make_pipeline()
        body = b'{"model": "gpt-4o", "messages": []}'

        result = await pipeline.process(make_request(body))

        assert result.status == 200
        assert len(session.calls) == 1
        assert session.calls[0]["data"] == body

    async def test_empty_body_forwarded_as_none(self) -> None:
        pipeline, session = make_pipeline()

        await pipeline.process(make_request(b""))

        assert session.calls[0]["data"] is None


class TestMutationOrdering:
    """Mutation must happen before scanning; scanned bytes == forwarded bytes."""

    async def test_scanner_sees_exact_forwarded_bytes(self) -> None:
        pipeline, session = make_pipeline()

        def add_marker(body_json: dict, target: UpstreamTarget) -> dict:
            body_json["mutated"] = True
            return body_json

        pipeline.add_mutator(add_marker)
        await pipeline.process(make_request(b'{"model": "gpt-4o"}'))

        forwarded = session.calls[0]["data"]
        scanned_text = pipeline._scanner.scan_async.call_args[0][0]
        assert scanned_text.encode() == forwarded
        assert json.loads(forwarded)["mutated"] is True

    async def test_no_change_mutator_keeps_raw_bytes(self) -> None:
        pipeline, session = make_pipeline()
        pipeline.add_mutator(lambda body_json, target: None)
        body = b'{"model":   "gpt-4o"}'  # spacing must survive untouched

        await pipeline.process(make_request(body))

        assert session.calls[0]["data"] == body

    async def test_invalid_json_fails_open_to_raw_bytes(self) -> None:
        pipeline, session = make_pipeline()
        pipeline.add_mutator(lambda body_json, target: {"replaced": True})
        body = b"not json at all"

        await pipeline.process(make_request(body))

        assert session.calls[0]["data"] == body

    async def test_mutator_exception_is_skipped(self) -> None:
        pipeline, session = make_pipeline()

        def broken(body_json: dict, target: UpstreamTarget) -> dict:
            raise RuntimeError("boom")

        pipeline.add_mutator(broken)
        body = b'{"model": "gpt-4o"}'

        result = await pipeline.process(make_request(body))

        assert result.status == 200
        assert session.calls[0]["data"] == body


class TestDetectionReporting:
    """Detections must be reported to the control plane from the shared pipeline."""

    async def test_block_reports_to_control_plane(self) -> None:
        pipeline, session = make_pipeline(scan_action="block")
        cp_client = MagicMock()
        cp_client.report_detection = AsyncMock()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp_client):
            result = await pipeline.process(
                make_request(b'{"model": "gpt-4", "messages": []}')
            )
            await asyncio.sleep(0)  # let the fire-and-forget task run

        assert result.status == 400
        assert json.loads(result.body)["error"]["type"] == "content_blocked"
        assert session.calls == []  # blocked requests must not reach upstream
        cp_client.report_detection.assert_called_once()
        kwargs = cp_client.report_detection.call_args.kwargs
        assert kwargs["event_type"] == "block"
        assert kwargs["provider"] == "openai"
        assert kwargs["model"] == "gpt-4"
        assert kwargs["input_tokens"] is not None

    async def test_warn_reports_to_control_plane_and_forwards(self) -> None:
        pipeline, session = make_pipeline(scan_action="warn")
        cp_client = MagicMock()
        cp_client.report_detection = AsyncMock()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp_client):
            result = await pipeline.process(make_request(b'{"model": "gpt-4"}'))
            await asyncio.sleep(0)

        assert result.status == 200
        assert len(session.calls) == 1
        assert cp_client.report_detection.call_args.kwargs["event_type"] == "warn"

    async def test_no_control_plane_client_is_fine(self) -> None:
        pipeline, _ = make_pipeline(scan_action="block")

        with patch("aiproxyguard.pipeline.get_client", return_value=None):
            result = await pipeline.process(make_request(b'{"model": "gpt-4"}'))

        assert result.status == 400


class TestAuthHeaderSelection:
    """Exactly one auth header is forwarded, with the configured one prioritized."""

    async def test_configured_auth_header_wins(self) -> None:
        pipeline, session = make_pipeline()
        request = make_request(
            b'{"model": "gpt-4o"}',
            headers={
                "content-type": "application/json",
                "x-api-key": "key-a",
                "authorization": "Bearer key-b",
            },
        )
        request.target.auth_header = "x-api-key"

        await pipeline.process(request)

        headers = session.calls[0]["headers"]
        assert headers["x-api-key"] == "key-a"
        assert "authorization" not in headers

    async def test_fallback_order_when_unconfigured(self) -> None:
        pipeline, session = make_pipeline()
        request = make_request(
            b'{"model": "gpt-4o"}',
            headers={
                "content-type": "application/json",
                "authorization": "Bearer key-b",
                "api-key": "key-c",
            },
        )
        request.target.auth_header = None

        await pipeline.process(request)

        headers = session.calls[0]["headers"]
        assert headers["authorization"] == "Bearer key-b"
        assert "api-key" not in headers


class TestFailureModes:
    async def test_scanner_timeout_closed_returns_503(self) -> None:
        config = MockConfig(security=MockSecurityConfig(failure_mode="closed"))
        pipeline, session = make_pipeline(config=config)

        async def slow_scan(text: str) -> SimpleNamespace:
            await asyncio.sleep(10)
            return make_scan_result()

        pipeline._scanner.scan_async = slow_scan
        pipeline._config.security.scanner_timeout_ms = 10

        result = await pipeline.process(make_request(b'{"model": "gpt-4o"}'))

        assert result.status == 503
        assert session.calls == []

    async def test_scanner_timeout_open_forwards(self) -> None:
        pipeline, session = make_pipeline()

        async def slow_scan(text: str) -> SimpleNamespace:
            await asyncio.sleep(10)
            return make_scan_result()

        pipeline._scanner.scan_async = slow_scan
        pipeline._config.security.scanner_timeout_ms = 10

        result = await pipeline.process(make_request(b'{"model": "gpt-4o"}'))

        assert result.status == 200
        assert len(session.calls) == 1


class TestResponseScanTimeout:
    """Response-scan timeout must fail open regardless of failure_mode.

    A timeout is not a detection, and the upstream response already succeeded
    (and was billed) -- a slow secondary scan must never convert it into a 502.
    """

    def _pipeline_with_slow_response_scanner(self, failure_mode: str):
        config = MockConfig(security=MockSecurityConfig(failure_mode=failure_mode))
        config.security.scanner_timeout_ms = 10
        pipeline, session = make_pipeline(config=config)

        rscanner = MagicMock()
        rscanner.enabled = True

        def slow(text: str):
            # Longer than scanner_timeout_ms (10ms) so wait_for fires, but short
            # enough that the uncancellable worker thread doesn't hang teardown.
            import time as _t
            _t.sleep(0.2)
            return SimpleNamespace(blocked=False, has_detections=False,
                                   category=None, signature_id=None, details={})

        rscanner.scan = slow
        pipeline._scanner.response_scanner = rscanner
        return pipeline, session

    async def test_response_timeout_open_passes_through(self) -> None:
        pipeline, session = self._pipeline_with_slow_response_scanner("open")
        result = await pipeline.process(make_request(b'{"model": "gpt-4o"}'))
        assert result.status == 200

    async def test_response_timeout_closed_still_passes_through(self) -> None:
        # The behavior that changed: closed mode must NOT block on a response
        # scan timeout (it still blocks on a genuine response detection).
        pipeline, session = self._pipeline_with_slow_response_scanner("closed")
        result = await pipeline.process(make_request(b'{"model": "gpt-4o"}'))
        assert result.status == 200


class TestUsageReporting:
    """Billed-token usage events for allowed (forwarded) requests."""

    OPENAI_BODY = (
        b'{"id": "chatcmpl-1", "model": "gpt-4o-2024-08-06",'
        b' "choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 34}}'
    )

    def _cp_client(self) -> MagicMock:
        cp = MagicMock()
        cp.report_usage = AsyncMock()
        cp.report_detection = AsyncMock()
        return cp

    async def test_usage_reported_on_success(self) -> None:
        pipeline, session = make_pipeline(
            session=FakeSession(FakeResponse(status=200, body=self.OPENAI_BODY))
        )
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            result = await pipeline.process(make_request(b'{"model": "gpt-4o"}'))
            await asyncio.sleep(0)

        assert result.status == 200
        cp.report_usage.assert_called_once()
        kwargs = cp.report_usage.call_args.kwargs
        assert kwargs["provider"] == "openai"
        assert kwargs["model"] == "gpt-4o-2024-08-06"  # response model, not request alias
        assert kwargs["input_tokens"] == 12
        assert kwargs["output_tokens"] == 34
        assert kwargs["latency_ms"] >= 0

    async def test_no_usage_event_on_upstream_error(self) -> None:
        error_body = b'{"error": {"message": "invalid api key"}}'
        pipeline, _ = make_pipeline(
            session=FakeSession(FakeResponse(status=401, body=error_body))
        )
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            result = await pipeline.process(make_request(b'{"model": "gpt-4o"}'))
            await asyncio.sleep(0)

        assert result.status == 401
        cp.report_usage.assert_not_called()

    async def test_no_usage_event_without_usage_field(self) -> None:
        pipeline, _ = make_pipeline(
            session=FakeSession(FakeResponse(status=200, body=b'{"ok": true}'))
        )
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(b'{"model": "gpt-4o"}'))
            await asyncio.sleep(0)

        cp.report_usage.assert_not_called()

    async def test_no_usage_event_on_non_json_response(self) -> None:
        pipeline, _ = make_pipeline(
            session=FakeSession(FakeResponse(status=200, body=b"data: chunk\n\n"))
        )
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(b'{"model": "gpt-4o"}'))
            await asyncio.sleep(0)

        cp.report_usage.assert_not_called()

    async def test_anthropic_usage_shape(self) -> None:
        body = (
            b'{"id": "msg_1", "model": "claude-sonnet-4-5",'
            b' "usage": {"input_tokens": 7, "output_tokens": 21}}'
        )
        pipeline, _ = make_pipeline(session=FakeSession(FakeResponse(status=200, body=body)))
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(b'{"model": "claude-sonnet-4-5"}'))
            await asyncio.sleep(0)

        kwargs = cp.report_usage.call_args.kwargs
        assert kwargs["input_tokens"] == 7
        assert kwargs["output_tokens"] == 21

    async def test_anthropic_cache_read_reported(self) -> None:
        body = (
            b'{"id": "msg_1", "model": "claude-sonnet-4-5",'
            b' "usage": {"input_tokens": 7, "output_tokens": 21,'
            b' "cache_read_input_tokens": 900}}'
        )
        pipeline, _ = make_pipeline(session=FakeSession(FakeResponse(status=200, body=body)))
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(b'{"model": "claude-sonnet-4-5"}'))
            await asyncio.sleep(0)

        assert cp.report_usage.call_args.kwargs["cache_read_tokens"] == 900

    async def test_no_routing_provenance_when_not_routed(self) -> None:
        pipeline, _ = make_pipeline(
            session=FakeSession(FakeResponse(status=200, body=self.OPENAI_BODY))
        )
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(b'{"model": "gpt-4o"}'))
            await asyncio.sleep(0)

        kwargs = cp.report_usage.call_args.kwargs
        assert kwargs["requested_model"] is None
        assert kwargs["routed_model"] is None
        assert kwargs["routing_mode"] is None
        assert kwargs["cache_read_tokens"] is None

    async def test_applied_downgrade_provenance(self) -> None:
        mini_body = (
            b'{"id": "chatcmpl-1", "model": "gpt-4o-mini",'
            b' "usage": {"prompt_tokens": 12, "completion_tokens": 34}}'
        )
        pipeline, _ = make_pipeline(
            config=_downgrade_config(dry_run=False),
            session=FakeSession(FakeResponse(status=200, body=mini_body)),
        )
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(
                b'{"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}'
            ))
            await asyncio.sleep(0)

        kwargs = cp.report_usage.call_args.kwargs
        assert kwargs["requested_model"] == "gpt-4o"
        assert kwargs["routed_model"] == "gpt-4o-mini"
        assert kwargs["routing_mode"] == "applied"

    async def test_dry_run_downgrade_provenance(self) -> None:
        pipeline, _ = make_pipeline(
            config=_downgrade_config(dry_run=True),
            session=FakeSession(FakeResponse(status=200, body=self.OPENAI_BODY)),
        )
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(
                b'{"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}'
            ))
            await asyncio.sleep(0)

        kwargs = cp.report_usage.call_args.kwargs
        assert kwargs["requested_model"] == "gpt-4o"
        assert kwargs["routed_model"] == "gpt-4o-mini"
        assert kwargs["routing_mode"] == "dry_run"  # not rewritten, only projected

    async def test_alias_routing_provenance(self) -> None:
        cfg = _routing_config({"summarize": {"ordered_pool": ["gpt-4o-mini"]}})
        mini_body = (
            b'{"id": "chatcmpl-1", "model": "gpt-4o-mini",'
            b' "usage": {"prompt_tokens": 12, "completion_tokens": 34}}'
        )
        pipeline, _ = make_pipeline(
            config=cfg, session=FakeSession(FakeResponse(status=200, body=mini_body))
        )
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(b'{"model": "router:summarize", "messages": []}'))
            await asyncio.sleep(0)

        kwargs = cp.report_usage.call_args.kwargs
        assert kwargs["requested_model"] == "router:summarize"
        assert kwargs["routed_model"] == "gpt-4o-mini"
        assert kwargs["routing_mode"] == "applied"

    async def test_alias_fallback_reports_final_served_model(self) -> None:
        # router:t routes to "a"; a 5xx forces fallback to "b". Usage telemetry
        # must report the model actually served ("b"), not the stale first choice.
        cfg = _routing_config({"t": {"ordered_pool": ["a", "b"]}})
        ok_body = b'{"model": "b", "usage": {"prompt_tokens": 5, "completion_tokens": 9}}'
        session = _SequenceSession([
            FakeResponse(status=503, body=b'{"err": 1}'),
            FakeResponse(status=200, body=ok_body),
        ])
        pipeline, _ = make_pipeline(config=cfg, session=session)
        cp = self._cp_client()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(b'{"model": "router:t", "messages": []}'))
            await asyncio.sleep(0)

        kwargs = cp.report_usage.call_args.kwargs
        assert kwargs["requested_model"] == "router:t"
        assert kwargs["routed_model"] == "b"  # final served model, not "a"
        assert kwargs["routing_mode"] == "applied"

    async def test_usage_reported_even_when_response_blocked(self) -> None:
        """The provider billed for the completion even if the proxy blocks
        the response -- usage must still be accounted."""
        pipeline, _ = make_pipeline(
            session=FakeSession(FakeResponse(status=200, body=self.OPENAI_BODY))
        )
        cp = self._cp_client()

        rscanner = MagicMock()
        rscanner.enabled = True
        rscanner.scan.return_value = SimpleNamespace(
            blocked=True, has_detections=True,
            category="data-leak", signature_id="DL-1", details={},
        )
        pipeline._scanner.response_scanner = rscanner

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            result = await pipeline.process(make_request(b'{"model": "gpt-4o"}'))
            await asyncio.sleep(0)

        assert result.status == 502  # response blocked
        cp.report_usage.assert_called_once()  # but billing still accounted
        assert cp.report_usage.call_args.kwargs["input_tokens"] == 12

    async def test_no_parse_when_usage_reporting_disabled(self) -> None:
        """When usage reporting is off, the response body must not be parsed
        on the response path (cheap gate before any work)."""
        pipeline, _ = make_pipeline(
            session=FakeSession(FakeResponse(status=200, body=self.OPENAI_BODY))
        )
        cp = MagicMock()
        cp.usage_reporting_enabled = False
        cp.report_usage = AsyncMock()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            with patch("aiproxyguard.pipeline.json.loads") as mock_loads:
                await pipeline.process(make_request(b'{"model": "gpt-4o"}'))
                await asyncio.sleep(0)
                mock_loads.assert_not_called()
        cp.report_usage.assert_not_called()


class TestMutatorScannerCoherence:
    """An Anthropic cache mutator must run before scanning, and the scanner +
    the forwarded bytes must both see the mutated body (the #310 invariant)."""

    async def test_cache_injection_seen_by_scanner_and_forwarded(self) -> None:
        from aiproxyguard.cost_optimization import inject_anthropic_cache_control

        pipeline, session = make_pipeline()
        pipeline.add_mutator(inject_anthropic_cache_control)

        request = make_request(
            b'{"model": "claude-sonnet-4-5", "system": "You are helpful."}'
        )
        request.target.provider = "anthropic"
        request.target.url = "https://api.anthropic.com/v1/messages"

        await pipeline.process(request)

        # scanner saw the mutated payload...
        scanned = pipeline._scanner.scan_async.call_args[0][0]
        assert "cache_control" in scanned
        # ...and the exact same bytes were forwarded upstream
        forwarded = session.calls[0]["data"]
        assert scanned.encode() == forwarded
        body = json.loads(forwarded)
        assert body["system"][0]["cache_control"] == {"type": "ephemeral"}

    async def test_non_anthropic_request_unchanged(self) -> None:
        from aiproxyguard.cost_optimization import inject_anthropic_cache_control

        pipeline, session = make_pipeline()
        pipeline.add_mutator(inject_anthropic_cache_control)

        original = b'{"model": "gpt-4o", "system": "You are helpful."}'
        await pipeline.process(make_request(original))  # provider=openai by default

        # untouched: forwarded byte-identical to the original
        assert session.calls[0]["data"] == original


class _SequenceSession:
    """FakeSession variant that returns a queued response per request call."""

    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = responses
        self.calls: list[dict] = []

    def request(self, **kwargs: object) -> FakeResponse:
        self.calls.append(kwargs)
        idx = min(len(self.calls) - 1, len(self._responses) - 1)
        return self._responses[idx]


def _routing_config(tasks: dict) -> MockConfig:
    cfg = MockConfig()
    cfg.routing.tasks = tasks
    return cfg


class TestRouterAlias:
    """#305 1a: model: router:<task> resolves to a concrete model pre-forward."""

    async def test_alias_rewrites_model_to_cheapest(self) -> None:
        cfg = _routing_config({"summarize": {"ordered_pool": ["gpt-4o-mini", "gpt-4o"]}})
        pipeline, session = make_pipeline(config=cfg)

        result = await pipeline.process(
            make_request(b'{"model": "router:summarize", "messages": []}')
        )

        assert result.status == 200
        forwarded = json.loads(session.calls[0]["data"])
        assert forwarded["model"] == "gpt-4o-mini"
        # decision surfaced on the response
        assert result.headers["x-aiproxyguard-routed-model"] == "gpt-4o-mini"

    async def test_scanner_sees_rewritten_model(self) -> None:
        cfg = _routing_config({"t": {"ordered_pool": ["cheap"]}})
        pipeline, session = make_pipeline(config=cfg)

        await pipeline.process(make_request(b'{"model": "router:t", "messages": []}'))

        scanned = pipeline._scanner.scan_async.call_args[0][0]
        assert json.loads(scanned)["model"] == "cheap"

    async def test_unknown_task_fails_closed_400(self) -> None:
        cfg = _routing_config({"known": {"ordered_pool": ["m"]}})
        pipeline, session = make_pipeline(config=cfg)

        result = await pipeline.process(
            make_request(b'{"model": "router:nope", "messages": []}')
        )

        assert result.status == 400
        assert b"unknown_router_task" in result.body
        assert len(session.calls) == 0  # never forwarded upstream

    async def test_empty_pool_fails_closed_400(self) -> None:
        cfg = _routing_config({"t": {"ordered_pool": []}})
        pipeline, session = make_pipeline(config=cfg)

        result = await pipeline.process(make_request(b'{"model": "router:t"}'))

        assert result.status == 400
        assert b"no_route" in result.body

    async def test_capability_filter_prefers_fallback(self) -> None:
        cfg = _routing_config({
            "t": {"ordered_pool": ["mini"], "fallback": ["strong"]}
        })
        pipeline, session = make_pipeline(config=cfg)

        # tools present -> not capable -> fallback model chosen
        await pipeline.process(
            make_request(b'{"model": "router:t", "tools": [{"x": 1}]}')
        )

        assert json.loads(session.calls[0]["data"])["model"] == "strong"

    async def test_non_router_model_untouched(self) -> None:
        cfg = _routing_config({"t": {"ordered_pool": ["cheap"]}})
        pipeline, session = make_pipeline(config=cfg)
        body = b'{"model": "gpt-4o", "messages": []}'

        result = await pipeline.process(make_request(body))

        assert session.calls[0]["data"] == body
        assert "x-aiproxyguard-routed-model" not in result.headers


class TestRoutingFallbackRetry:
    """On upstream 5xx, retry the next model in the routing plan."""

    async def test_retries_next_model_on_5xx(self) -> None:
        cfg = _routing_config({"t": {"ordered_pool": ["a", "b"]}})
        session = _SequenceSession([
            FakeResponse(status=503, body=b'{"err": 1}'),
            FakeResponse(status=200, body=b'{"ok": true}'),
        ])
        pipeline, _ = make_pipeline(config=cfg, session=session)

        result = await pipeline.process(make_request(b'{"model": "router:t"}'))

        assert result.status == 200
        assert len(session.calls) == 2
        assert json.loads(session.calls[0]["data"])["model"] == "a"
        assert json.loads(session.calls[1]["data"])["model"] == "b"
        assert result.headers["x-aiproxyguard-routed-model"] == "b"
        # invariant: every forwarded body is scanned (initial + retry)
        assert pipeline._scanner.scan_async.call_count == 2
        rescanned = pipeline._scanner.scan_async.call_args_list[1][0][0]
        assert json.loads(rescanned)["model"] == "b"

    async def test_4xx_not_retried(self) -> None:
        cfg = _routing_config({"t": {"ordered_pool": ["a", "b"]}})
        session = _SequenceSession([
            FakeResponse(status=400, body=b'{"err": 1}'),
            FakeResponse(status=200, body=b'{"ok": true}'),
        ])
        pipeline, _ = make_pipeline(config=cfg, session=session)

        result = await pipeline.process(make_request(b'{"model": "router:t"}'))

        assert result.status == 400
        assert len(session.calls) == 1  # no retry on 4xx

    async def test_5xx_exhausts_plan_then_returns_last(self) -> None:
        cfg = _routing_config({"t": {"ordered_pool": ["a", "b"]}})
        session = _SequenceSession([FakeResponse(status=500, body=b'{"err": 1}')])
        pipeline, _ = make_pipeline(config=cfg, session=session)

        result = await pipeline.process(make_request(b'{"model": "router:t"}'))

        # primary + one retry (b), both 500 -> final 500 returned, bounded
        assert result.status == 500
        assert len(session.calls) == 2

    async def test_no_retry_without_routing_plan(self) -> None:
        session = _SequenceSession([FakeResponse(status=503, body=b'{"err": 1}')])
        pipeline, _ = make_pipeline(session=session)

        result = await pipeline.process(make_request(b'{"model": "gpt-4o"}'))

        assert result.status == 503
        assert len(session.calls) == 1  # plain request, no fallback


def _downgrade_config(dry_run: bool = True) -> MockConfig:
    cfg = MockConfig()
    cfg.routing.downgrades = [
        {"provider": "openai", "from": "gpt-4o", "to": "gpt-4o-mini"}
    ]
    cfg.routing.dry_run = dry_run
    return cfg


class TestTransparentDowngrade:
    """#305 1b: complexity-scored same-provider downgrade, dry-run by default."""

    async def test_dry_run_annotates_without_rewriting(self) -> None:
        pipeline, session = make_pipeline(config=_downgrade_config(dry_run=True))

        result = await pipeline.process(
            make_request(b'{"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}')
        )

        # model NOT rewritten upstream
        assert json.loads(session.calls[0]["data"])["model"] == "gpt-4o"
        # decision surfaced, but no routed-model header (no actual route)
        assert "x-aiproxyguard-routing-decision" in result.headers
        assert "gpt-4o-mini" in result.headers["x-aiproxyguard-routing-decision"]
        assert "x-aiproxyguard-routed-model" not in result.headers

    async def test_live_mode_rewrites_model(self) -> None:
        pipeline, session = make_pipeline(config=_downgrade_config(dry_run=False))

        result = await pipeline.process(
            make_request(b'{"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}')
        )

        assert json.loads(session.calls[0]["data"])["model"] == "gpt-4o-mini"
        assert result.headers["x-aiproxyguard-routed-model"] == "gpt-4o-mini"

    async def test_excluded_request_not_downgraded(self) -> None:
        pipeline, session = make_pipeline(config=_downgrade_config(dry_run=False))

        result = await pipeline.process(
            make_request(b'{"model": "gpt-4o", "tools": [{"x": 1}], "messages": [{"role": "user", "content": "hi"}]}')
        )

        assert json.loads(session.calls[0]["data"])["model"] == "gpt-4o"  # unchanged
        assert "x-aiproxyguard-routed-model" not in result.headers

    async def test_complex_prompt_not_downgraded(self) -> None:
        pipeline, session = make_pipeline(config=_downgrade_config(dry_run=False))

        # 2+ reasoning markers -> strong tier -> not downgrade-eligible
        body = b'{"model": "gpt-4o", "messages": [{"role": "user", "content": "Explain why and reason through this carefully"}]}'
        result = await pipeline.process(make_request(body))

        assert json.loads(session.calls[0]["data"])["model"] == "gpt-4o"
        assert "x-aiproxyguard-routed-model" not in result.headers

    async def test_no_downgrade_without_config(self) -> None:
        pipeline, session = make_pipeline()  # default: no downgrades
        result = await pipeline.process(
            make_request(b'{"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}')
        )
        assert json.loads(session.calls[0]["data"])["model"] == "gpt-4o"
        assert "x-aiproxyguard-routing-decision" not in result.headers


class TestDowngradeIntegrationEdges:
    """Edge contracts for transparent downgrade."""

    async def test_alias_routed_request_never_downgraded(self) -> None:
        cfg = _routing_config({"t": {"ordered_pool": ["cheap"]}})
        cfg.routing.downgrades = [{"provider": "openai", "from": "cheap", "to": "cheaper"}]
        cfg.routing.dry_run = True
        pipeline, session = make_pipeline(config=cfg)

        result = await pipeline.process(make_request(b'{"model": "router:t", "messages": [{"role": "user", "content": "hi"}]}'))

        # alias routed to "cheap"; downgrade must NOT also fire
        assert result.headers["x-aiproxyguard-routed-model"] == "cheap"
        assert "x-aiproxyguard-routing-decision" not in result.headers
        assert json.loads(session.calls[0]["data"])["model"] == "cheap"

    async def test_empty_prompt_not_downgraded(self) -> None:
        pipeline, session = make_pipeline(config=_downgrade_config(dry_run=False))
        # no extractable prompt text -> fail closed (no downgrade)
        result = await pipeline.process(make_request(b'{"model": "gpt-4o", "messages": []}'))
        assert json.loads(session.calls[0]["data"])["model"] == "gpt-4o"
        assert "x-aiproxyguard-routed-model" not in result.headers

    async def test_default_dry_run_does_not_rewrite(self) -> None:
        # MockRoutingConfig.dry_run defaults True; a configured downgrade only
        # annotates unless dry_run is explicitly false.
        cfg = MockConfig()
        cfg.routing.downgrades = [{"provider": "openai", "from": "gpt-4o", "to": "gpt-4o-mini"}]
        pipeline, session = make_pipeline(config=cfg)
        result = await pipeline.process(
            make_request(b'{"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}')
        )
        assert json.loads(session.calls[0]["data"])["model"] == "gpt-4o"  # not rewritten
        assert "x-aiproxyguard-routing-decision" in result.headers


class _FakeCache:
    """Stand-in ResponseCache for pipeline integration tests."""

    def __init__(self, enabled=True, hit: CachedResponse | None = None):
        self.enabled = enabled
        self._hit = hit
        self.stored: list[CachedResponse] = []
        self.stored_keys: list[str] = []

    def compute_key(self, provider, path, outbound):
        try:
            b = json.loads(outbound)
        except Exception:
            return None
        if not isinstance(b, dict) or not is_cacheable(b):
            return None
        # Model-aware key so tests can prove the store key tracks the served model.
        return f"ck:{b.get('model')}"

    async def get(self, key):
        return self._hit

    async def set(self, key, resp):
        self.stored_keys.append(key)
        self.stored.append(resp)


# A deterministic, cacheable request body (temperature 0, no tools/stream).
_CACHEABLE = b'{"model": "gpt-4o-mini", "temperature": 0, "messages": [{"role": "user", "content": "hi"}]}'


class TestResponseCache:
    async def test_miss_forwards_and_stores(self) -> None:
        cache = _FakeCache(hit=None)
        body = b'{"id":"x","model":"gpt-4o-mini","usage":{"prompt_tokens":5,"completion_tokens":7}}'
        pipeline, session = make_pipeline(session=FakeSession(FakeResponse(status=200, body=body)))
        pipeline._cache = cache

        result = await pipeline.process(make_request(_CACHEABLE))
        await asyncio.sleep(0)  # let the background store run

        assert len(session.calls) == 1  # upstream was called
        assert result.headers.get(CACHE_STATUS_HEADER) == "miss"
        assert len(cache.stored) == 1
        assert cache.stored[0].input_tokens == 5 and cache.stored[0].output_tokens == 7

    async def test_hit_serves_without_upstream(self) -> None:
        cached = CachedResponse(body=b'{"cached":true}', content_type="application/json",
                                input_tokens=5, output_tokens=7, model="gpt-4o-mini")
        cache = _FakeCache(hit=cached)
        pipeline, session = make_pipeline()
        pipeline._cache = cache

        result = await pipeline.process(make_request(_CACHEABLE))

        assert len(session.calls) == 0  # upstream NOT called
        assert result.body == b'{"cached":true}'
        assert result.headers.get(CACHE_STATUS_HEADER) == "hit"

    async def test_hit_still_runs_response_scan(self) -> None:
        # No policy bypass: a cache hit must still pass through response scanning.
        cached = CachedResponse(b'{"cached":true}', "application/json", 5, 7, "gpt-4o-mini")
        cache = _FakeCache(hit=cached)
        pipeline, session = make_pipeline()
        pipeline._cache = cache
        pipeline._scan_response = AsyncMock(return_value=PipelineResult(status=403, body=b"blocked"))

        result = await pipeline.process(make_request(_CACHEABLE))

        pipeline._scan_response.assert_awaited_once()
        assert result.status == 403  # the scan block wins over the cached body
        assert len(session.calls) == 0

    async def test_opt_out_disables_cache(self) -> None:
        # cost_optimization.response_cache is the live per-policy opt-in (#307
        # phase 3): even with Redis wired and a hit available, an opted-out
        # policy forwards upstream and never serves from cache.
        cached = CachedResponse(b'{"cached":true}', "application/json", 5, 7, "gpt-4o-mini")
        cache = _FakeCache(hit=cached)
        pipeline, session = make_pipeline()
        pipeline._cache = cache
        pipeline._config.cost_optimization.response_cache = False

        result = await pipeline.process(make_request(_CACHEABLE))
        await asyncio.sleep(0)  # let any (unexpected) background store run

        assert len(session.calls) == 1  # forwarded, not served from cache
        assert CACHE_STATUS_HEADER not in result.headers
        assert cache.stored == []  # opted out -> nothing written to cache either

    async def test_hot_toggle_via_pushed_cost_optimization(self) -> None:
        # End-to-end: the real control-plane cost_optimization handler shares the
        # pipeline's config, so pushing response_cache off/on stops/starts caching
        # without a restart.
        from aiproxyguard.server import register_control_plane_callbacks

        cached = CachedResponse(b'{"cached":true}', "application/json", 5, 7, "gpt-4o-mini")
        cache = _FakeCache(hit=cached)
        pipeline, session = make_pipeline()
        pipeline._cache = cache

        cp = MagicMock()
        register_control_plane_callbacks(
            cp, scanner=MagicMock(), policy=MagicMock(),
            config=pipeline._config, metrics=MagicMock(),
        )
        handler = next(
            c.args[1] for c in cp.register_section_handler.call_args_list
            if c.args and c.args[0] == "cost_optimization"
        )

        # Push OFF -> next request forwards upstream (no hit).
        handler({"response_cache": "false"})
        r_off = await pipeline.process(make_request(_CACHEABLE))
        assert len(session.calls) == 1
        assert CACHE_STATUS_HEADER not in r_off.headers

        # Push ON -> next identical request is served from cache, no new upstream call.
        handler({"response_cache": "true"})
        r_on = await pipeline.process(make_request(_CACHEABLE))
        assert len(session.calls) == 1
        assert r_on.headers.get(CACHE_STATUS_HEADER) == "hit"

    async def test_pii_policy_disables_cache(self) -> None:
        # Reads the LIVE policy engine; enabling pii after startup disables caching.
        cached = CachedResponse(b'{"cached":true}', "application/json", 5, 7, "gpt-4o-mini")
        cache = _FakeCache(hit=cached)
        pipeline, session = make_pipeline()
        pipeline._cache = cache
        pipeline._policy.categories = {"pii": {"action": "block"}}

        result = await pipeline.process(make_request(_CACHEABLE))

        assert len(session.calls) == 1  # forwarded, not served from cache
        assert CACHE_STATUS_HEADER not in result.headers

    async def test_hit_preserves_stored_status(self) -> None:
        cached = CachedResponse(b'{"ok":1}', "application/json", 1, 1, "gpt-4o-mini", status=201)
        pipeline, session = make_pipeline()
        pipeline._cache = _FakeCache(hit=cached)

        result = await pipeline.process(make_request(_CACHEABLE))

        assert result.status == 201  # not coerced to 200
        assert result.headers.get(CACHE_STATUS_HEADER) == "hit"

    async def test_non_2xx_not_stored(self) -> None:
        cache = _FakeCache(hit=None)
        pipeline, session = make_pipeline(
            session=FakeSession(FakeResponse(status=400, body=b'{"error":"bad"}'))
        )
        pipeline._cache = cache

        await pipeline.process(make_request(_CACHEABLE))
        await asyncio.sleep(0)

        assert len(cache.stored) == 0  # non-2xx never cached

    async def test_fallback_stores_under_served_model_key(self) -> None:
        # Alias routes to "a"; a 5xx forces fallback to "b". The response must be
        # stored under b's key (the model that produced it), never a's.
        cfg = _routing_config({"t": {"ordered_pool": ["a", "b"]}})
        ok_body = b'{"model":"b","usage":{"prompt_tokens":5,"completion_tokens":9}}'
        session = _SequenceSession([
            FakeResponse(status=503, body=b'{"err":1}'),
            FakeResponse(status=200, body=ok_body),
        ])
        pipeline, _ = make_pipeline(config=cfg, session=session)
        cache = _FakeCache(hit=None)
        pipeline._cache = cache

        await pipeline.process(make_request(b'{"model":"router:t","temperature":0,"messages":[{"role":"user","content":"hi"}]}'))
        await asyncio.sleep(0)

        assert cache.stored_keys == ["ck:b"]  # served model, not "ck:a"

    async def test_ineligible_request_not_cached(self) -> None:
        cache = _FakeCache(hit=CachedResponse(b'{"cached":true}', "application/json", 0, 0, None))
        pipeline, session = make_pipeline()
        pipeline._cache = cache
        # temperature 0.7 -> non-deterministic -> ineligible
        body = b'{"model": "gpt-4o-mini", "temperature": 0.7, "messages": [{"role": "user", "content": "hi"}]}'

        result = await pipeline.process(make_request(body))
        await asyncio.sleep(0)

        assert len(session.calls) == 1  # forwarded (no hit despite cache having data)
        assert CACHE_STATUS_HEADER not in result.headers
        assert len(cache.stored) == 0

    async def test_served_hit_reports_cache_usage_event(self) -> None:
        # A served hit emits a usage event carrying the avoided (cached) tokens
        # as savings, with zero real spend (the upstream call was skipped).
        cached = CachedResponse(b'{"cached":true}', "application/json", 5, 7, "gpt-4o-mini")
        pipeline, session = make_pipeline()
        pipeline._cache = _FakeCache(hit=cached)
        cp = MagicMock()
        cp.report_usage = AsyncMock()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(_CACHEABLE))
            await asyncio.sleep(0)

        assert len(session.calls) == 0  # upstream NOT called
        cp.report_usage.assert_called_once()
        kwargs = cp.report_usage.call_args.kwargs
        assert kwargs["cache_hit"] is True
        assert kwargs["input_tokens"] == 0 and kwargs["output_tokens"] == 0
        assert kwargs["cached_input_tokens"] == 5
        assert kwargs["cached_output_tokens"] == 7
        assert kwargs["model"] == "gpt-4o-mini"

    async def test_blocked_hit_does_not_report_cache_usage(self) -> None:
        # A cache hit that the response scanner blocks delivered no value, so it
        # must NOT accrue savings.
        cached = CachedResponse(b'{"cached":true}', "application/json", 5, 7, "gpt-4o-mini")
        pipeline, session = make_pipeline()
        pipeline._cache = _FakeCache(hit=cached)
        pipeline._scan_response = AsyncMock(
            return_value=PipelineResult(status=403, body=b"blocked")
        )
        cp = MagicMock()
        cp.report_usage = AsyncMock()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            result = await pipeline.process(make_request(_CACHEABLE))
            await asyncio.sleep(0)

        assert result.status == 403
        cp.report_usage.assert_not_called()

    async def test_served_hit_preserves_zero_cached_tokens(self) -> None:
        # A genuine 0 must stay 0 (known zero), never collapse to None (unknown).
        cached = CachedResponse(b'{"cached":true}', "application/json", 0, 0, "gpt-4o-mini")
        pipeline, _ = make_pipeline()
        pipeline._cache = _FakeCache(hit=cached)
        cp = MagicMock()
        cp.report_usage = AsyncMock()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(_CACHEABLE))
            await asyncio.sleep(0)

        kwargs = cp.report_usage.call_args.kwargs
        assert kwargs["cached_input_tokens"] == 0
        assert kwargs["cached_output_tokens"] == 0

    async def test_non_2xx_hit_does_not_report_cache_usage(self) -> None:
        # The 2xx gate guards against attributing savings to a non-success hit.
        cached = CachedResponse(b'{"err":1}', "application/json", 5, 7, "gpt-4o-mini", status=404)
        pipeline, _ = make_pipeline()
        pipeline._cache = _FakeCache(hit=cached)
        cp = MagicMock()
        cp.report_usage = AsyncMock()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(_CACHEABLE))
            await asyncio.sleep(0)

        cp.report_usage.assert_not_called()

    async def test_served_hit_latency_excludes_scan(self) -> None:
        # Reported hit latency is the cache-serving cost only; a slow response
        # scan must not inflate it (mirrors the miss path's pre-scan duration).
        cached = CachedResponse(b'{"cached":true}', "application/json", 5, 7, "gpt-4o-mini")
        pipeline, _ = make_pipeline()
        pipeline._cache = _FakeCache(hit=cached)

        async def _slow_scan(*_args, **_kwargs):
            await asyncio.sleep(0.05)
            return None

        pipeline._scan_response = _slow_scan
        cp = MagicMock()
        cp.report_usage = AsyncMock()

        with patch("aiproxyguard.pipeline.get_client", return_value=cp):
            await pipeline.process(make_request(_CACHEABLE))
            await asyncio.sleep(0)

        # The 50ms scan must be excluded from the reported cache-hit latency.
        assert cp.report_usage.call_args.kwargs["latency_ms"] < 50
