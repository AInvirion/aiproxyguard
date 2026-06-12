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
    PipelineRequest,
    RequestPipeline,
    UpstreamTarget,
)


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


@dataclass
class MockConfig:
    security: MockSecurityConfig = field(default_factory=MockSecurityConfig)
    scanner: MockScannerConfig = field(default_factory=MockScannerConfig)


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
