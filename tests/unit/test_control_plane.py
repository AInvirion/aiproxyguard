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

"""Tests for the control plane client."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import pytest

from aiproxyguard.control_plane import (
    ControlPlaneClient,
    TelemetryEvent,
    _get_fingerprint,
    _get_instance_id,
)


@dataclass
class MockControlPlaneConfig:
    """Mock control plane configuration."""

    enabled: bool = True
    url: str = "https://api.test.example.com"
    api_key: str = "test-api-key"
    heartbeat_interval: int = 60
    sync_signatures: bool = True
    report_telemetry: bool = True
    report_usage: bool = True
    manifest_public_key: str = ""


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_instance_id_is_stable(self):
        """Instance ID should be stable across calls."""
        id1 = _get_instance_id()
        id2 = _get_instance_id()
        assert id1 == id2
        assert len(id1) == 32  # SHA256 truncated to 32 chars

    def test_get_fingerprint_is_stable(self):
        """Fingerprint should be stable across calls."""
        fp1 = _get_fingerprint()
        fp2 = _get_fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 16  # SHA256 truncated to 16 chars


class TestTelemetryEvent:
    """Tests for TelemetryEvent dataclass."""

    def test_telemetry_event_creation(self):
        """TelemetryEvent should be created with required fields."""
        event = TelemetryEvent(
            event_type="detection",
            category="prompt_injection",
            signature_id="sig_001",
            latency_ms=15,
            provider="openai",
            endpoint="/v1/chat/completions",
        )
        assert event.event_type == "detection"
        assert event.category == "prompt_injection"
        assert event.signature_id == "sig_001"
        assert event.latency_ms == 15
        assert event.timestamp is not None

    def test_telemetry_event_defaults(self):
        """TelemetryEvent should have sensible defaults."""
        event = TelemetryEvent(event_type="block", category="jailbreak")
        assert event.signature_id is None
        assert event.latency_ms is None
        assert event.provider is None
        assert event.endpoint is None

    def test_telemetry_event_with_model_and_tokens(self):
        """Test TelemetryEvent includes model and input_tokens fields."""
        event = TelemetryEvent(
            event_type="block",
            category="prompt_injection",
            signature_id="PI-001",
            latency_ms=12,
            provider="openai",
            endpoint="/v1/chat/completions",
            model="gpt-4o",
            input_tokens=1250,
        )

        assert event.model == "gpt-4o"
        assert event.input_tokens == 1250


class TestControlPlaneClient:
    """Tests for ControlPlaneClient."""

    def test_client_initialization(self):
        """Client should initialize with config."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config, version="1.0.0")

        assert client.config == config
        assert client.version == "1.0.0"
        assert client.instance_id
        assert client.fingerprint
        assert client._registered is False

    def test_client_disabled_skips_start(self):
        """Disabled client should skip start."""
        config = MockControlPlaneConfig(enabled=False)
        client = ControlPlaneClient(config)

        # start() should return immediately when disabled
        import asyncio

        asyncio.run(client.start())
        assert client._heartbeat_task is None

    @pytest.mark.asyncio
    async def test_report_detection_buffers_event(self):
        """report_detection should buffer events."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True  # Simulate successful registration

        await client.report_detection(
            event_type="detection",
            category="prompt_injection",
            signature_id="sig_001",
        )

        assert len(client._telemetry_buffer) == 1
        assert client._telemetry_buffer[0].event_type == "detection"
        assert client._telemetry_buffer[0].category == "prompt_injection"

    @pytest.mark.asyncio
    async def test_report_detection_skipped_when_not_registered(self):
        """report_detection should skip when not registered."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        # _registered is False by default

        await client.report_detection(
            event_type="detection",
            category="prompt_injection",
        )

        assert len(client._telemetry_buffer) == 0

    @pytest.mark.asyncio
    async def test_report_detection_skipped_when_disabled(self):
        """report_detection should skip when telemetry is disabled."""
        config = MockControlPlaneConfig(report_telemetry=False)
        client = ControlPlaneClient(config)
        client._registered = True

        await client.report_detection(
            event_type="detection",
            category="prompt_injection",
        )

        assert len(client._telemetry_buffer) == 0

    @pytest.mark.asyncio
    async def test_report_detection_accepts_model_and_tokens(self):
        """Test report_detection accepts model and input_tokens parameters."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True  # Simulate successful registration

        # This should not raise - just verify the signature accepts the params
        await client.report_detection(
            event_type="block",
            category="prompt_injection",
            signature_id="PI-001",
            latency_ms=12,
            provider="openai",
            endpoint="/v1/chat/completions",
            model="gpt-4o",
            input_tokens=1250,
        )
        # Verify event was buffered with correct fields
        assert len(client._telemetry_buffer) == 1
        event = client._telemetry_buffer[0]
        assert event.model == "gpt-4o"
        assert event.input_tokens == 1250

    def test_translate_policy_config(self):
        """Policy config translation should work correctly."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)

        cloud_config = {
            "detection": {
                "prompt_injection": {"enabled": True, "action": "warn", "threshold": 0.7},
                "jailbreak": {"enabled": True, "action": "block", "threshold": 0.8},
                "disabled_cat": {"enabled": False, "action": "block"},
            },
            "allowlists": [{"pattern": "test-*"}],
        }

        translated = client._translate_policy_config(cloud_config)

        assert "categories" in translated
        assert "prompt_injection" in translated["categories"]
        assert translated["categories"]["prompt_injection"]["action"] == "warn"
        assert translated["categories"]["prompt_injection"]["threshold"] == 0.7
        assert "disabled_cat" not in translated["categories"]
        assert translated["allowlists"] == [{"pattern": "test-*"}]

    def test_set_callbacks(self):
        """Callbacks should be settable."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)

        policy_callback = MagicMock()
        signature_callback = MagicMock()

        client.set_policy_update_callback(policy_callback)
        client.set_signature_update_callback(signature_callback)

        assert client._policy_update_callback == policy_callback
        assert client._signature_update_callback == signature_callback


class TestControlPlaneClientWithMockedHTTP:
    """Tests for ControlPlaneClient with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_register_success(self):
        """Registration should succeed and set _registered flag."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)

        # Mock the HTTP client
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()

        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client._register()

        assert client._registered is True
        client._client.post.assert_called_once()
        call_args = client._client.post.call_args
        assert "/api/v1/fleet/register" in str(call_args)

    @pytest.mark.asyncio
    async def test_flush_telemetry_sends_events(self):
        """Flush should send buffered events."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True

        # Add events to buffer
        client._telemetry_buffer = [
            TelemetryEvent(event_type="detection", category="test1"),
            TelemetryEvent(event_type="block", category="test2"),
        ]

        # Mock the HTTP client
        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_response.raise_for_status = MagicMock()

        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client._flush_telemetry()

        assert len(client._telemetry_buffer) == 0
        client._client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_signatures_returns_bundles(self):
        """fetch_signatures should return bundles from manifest."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)

        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(
            return_value={
                "version": "1.0.0",
                "bundles": [{"id": "bundle1"}, {"id": "bundle2"}],
            }
        )

        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_response)

        bundles = await client.fetch_signatures()

        assert len(bundles) == 2
        assert bundles[0]["id"] == "bundle1"

    @pytest.mark.asyncio
    async def test_fetch_signatures_disabled(self):
        """fetch_signatures should return empty when disabled."""
        config = MockControlPlaneConfig(sync_signatures=False)
        client = ControlPlaneClient(config)

        bundles = await client.fetch_signatures()

        assert bundles == []

    @pytest.mark.asyncio
    async def test_stop_cancels_heartbeat(self):
        """stop() should cancel heartbeat task and flush telemetry."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)

        # Create a real asyncio task that we can cancel
        async def dummy_task():
            await asyncio.sleep(1000)

        import asyncio

        client._heartbeat_task = asyncio.create_task(dummy_task())

        # Mock client close
        client._client = AsyncMock()
        client._client.aclose = AsyncMock()

        await client.stop()

        assert client._heartbeat_task.cancelled()
        assert client._client is None

    @pytest.mark.asyncio
    async def test_register_with_retry_succeeds_on_first_attempt(self):
        """Registration with retry should succeed on first attempt."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)

        # Mock successful registration
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client._register_with_retry(max_attempts=3)

        assert client._registered is True
        assert client._client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_register_with_retry_retries_on_failure(self):
        """Registration should retry on failure."""
        import httpx

        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)

        # Mock failed registration (HTTP error)
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock(side_effect=httpx.HTTPError("Connection failed"))
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client._register_with_retry(max_attempts=2)

        # Should have tried twice
        assert client._registered is False
        assert client._client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_heartbeat_loop_retries_registration(self):
        """Heartbeat loop should retry registration if not registered."""
        import asyncio

        config = MockControlPlaneConfig(heartbeat_interval=0)  # No delay
        client = ControlPlaneClient(config)
        client._registered = False

        # Mock HTTP client
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value={})
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        # Run heartbeat loop briefly
        task = asyncio.create_task(client._heartbeat_loop())
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have been registered during heartbeat
        assert client._registered is True

    @pytest.mark.asyncio
    async def test_telemetry_flush_includes_model_and_tokens(self):
        """Test that flushed telemetry includes model and input_tokens."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True

        # Mock the HTTP client
        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_response.raise_for_status = MagicMock()

        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client.report_detection(
            event_type="block",
            category="prompt_injection",
            model="gpt-4o",
            input_tokens=1250,
        )

        await client._flush_telemetry()

        # Verify the request was made with correct payload
        client._client.post.assert_called_once()
        call_args = client._client.post.call_args
        payload = call_args.kwargs["json"]
        event = payload["events"][0]
        assert event["model"] == "gpt-4o"
        assert event["input_tokens"] == 1250


class TestUsageReporting:
    """Tests for billed-token usage events and telemetry buffer safety rails."""

    @pytest.mark.asyncio
    async def test_report_usage_buffers_event(self):
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True

        await client.report_usage(
            provider="openai",
            endpoint="/openai/v1/chat/completions",
            model="gpt-4o-2024-08-06",
            input_tokens=12,
            output_tokens=34,
            latency_ms=250,
        )

        assert len(client._telemetry_buffer) == 1
        event = client._telemetry_buffer[0]
        assert event.event_type == "usage"
        assert event.category == "usage"
        assert event.input_tokens == 12
        assert event.output_tokens == 34
        assert event.model == "gpt-4o-2024-08-06"

    @pytest.mark.asyncio
    async def test_report_usage_gated_by_config_flag(self):
        config = MockControlPlaneConfig(report_usage=False)
        client = ControlPlaneClient(config)
        client._registered = True

        await client.report_usage(provider="openai", input_tokens=1, output_tokens=2)

        assert len(client._telemetry_buffer) == 0

    @pytest.mark.asyncio
    async def test_report_usage_gated_by_report_telemetry(self):
        config = MockControlPlaneConfig(report_telemetry=False)
        client = ControlPlaneClient(config)
        client._registered = True

        await client.report_usage(provider="openai", input_tokens=1, output_tokens=2)

        assert len(client._telemetry_buffer) == 0

    @pytest.mark.asyncio
    async def test_report_usage_skipped_when_not_registered(self):
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = False

        await client.report_usage(provider="openai", input_tokens=1, output_tokens=2)

        assert len(client._telemetry_buffer) == 0

    @pytest.mark.asyncio
    async def test_flush_chunks_large_buffers(self):
        """Buffers larger than the cloud's 100-event batch limit must be
        flushed in multiple posts, not one oversized rejected batch."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client._telemetry_buffer = [
            TelemetryEvent(event_type="usage", category="usage") for _ in range(250)
        ]

        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_response.raise_for_status = MagicMock()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client._flush_telemetry()

        assert len(client._telemetry_buffer) == 0
        assert client._client.post.call_count == 3  # 100 + 100 + 50
        for call in client._client.post.call_args_list:
            assert len(call.kwargs["json"]["events"]) <= 100

    @pytest.mark.asyncio
    async def test_flush_drops_chunk_on_4xx(self):
        """A 4xx rejection is permanent -- the chunk must be dropped, not
        re-buffered into an infinite retry loop."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client._telemetry_buffer = [
            TelemetryEvent(event_type="usage", category="usage") for _ in range(5)
        ]

        mock_response = AsyncMock()
        mock_response.status_code = 422
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client._flush_telemetry()

        assert len(client._telemetry_buffer) == 0  # dropped, not re-buffered

    @pytest.mark.asyncio
    async def test_flush_rebuffers_unsent_on_network_error(self):
        import httpx

        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client._telemetry_buffer = [
            TelemetryEvent(event_type="usage", category="usage") for _ in range(5)
        ]

        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=httpx.ConnectError("down"))

        await client._flush_telemetry()

        assert len(client._telemetry_buffer) == 5  # retained for retry

    @pytest.mark.asyncio
    async def test_buffer_capped_at_max(self):
        from aiproxyguard.control_plane import TELEMETRY_BUFFER_MAX

        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        # Simulate an unreachable CP: flush is a no-op that keeps the buffer
        client._telemetry_buffer = [
            TelemetryEvent(event_type="usage", category="usage")
            for _ in range(TELEMETRY_BUFFER_MAX)
        ]

        async def noop_flush():
            return None

        client._flush_telemetry = noop_flush  # type: ignore[method-assign]

        await client.report_usage(provider="openai", input_tokens=1, output_tokens=2)

        assert len(client._telemetry_buffer) == TELEMETRY_BUFFER_MAX

    @pytest.mark.asyncio
    async def test_flush_payload_includes_output_tokens(self):
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client._telemetry_buffer = [
            TelemetryEvent(
                event_type="usage", category="usage",
                provider="anthropic", model="claude-sonnet-4-5",
                input_tokens=7, output_tokens=21, latency_ms=300,
            ),
        ]

        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_response.raise_for_status = MagicMock()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client._flush_telemetry()

        event = client._client.post.call_args.kwargs["json"]["events"][0]
        assert event["event_type"] == "usage"
        assert event["input_tokens"] == 7
        assert event["output_tokens"] == 21


class TestMixedBatchIsolation:
    """Usage events must never poison detection telemetry in a shared batch."""

    @pytest.mark.asyncio
    async def test_usage_and_detection_events_sent_in_separate_posts(self):
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client._telemetry_buffer = [
            TelemetryEvent(event_type="block", category="prompt-injection"),
            TelemetryEvent(event_type="usage", category="usage"),
            TelemetryEvent(event_type="warn", category="jailbreak"),
            TelemetryEvent(event_type="usage", category="usage"),
        ]

        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_response.raise_for_status = MagicMock()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client._flush_telemetry()

        assert client._client.post.call_count == 2
        for call in client._client.post.call_args_list:
            types = {e["event_type"] for e in call.kwargs["json"]["events"]}
            # Each POST must be homogeneous: all-usage or no-usage
            assert types == {"usage"} or "usage" not in types

    @pytest.mark.asyncio
    async def test_usage_rejection_does_not_lose_detection_events(self):
        """Old control plane rejects usage events with 422; detection events
        in the same flush must still be delivered."""
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client._telemetry_buffer = [
            TelemetryEvent(event_type="block", category="prompt-injection"),
            TelemetryEvent(event_type="usage", category="usage"),
        ]

        delivered: list[list[str]] = []

        async def post(url, json):
            types = [e["event_type"] for e in json["events"]]
            resp = AsyncMock()
            resp.raise_for_status = MagicMock()
            if "usage" in types:
                resp.status_code = 422  # old cloud: unknown event_type
            else:
                resp.status_code = 201
                delivered.append(types)
            return resp

        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=post)

        await client._flush_telemetry()

        assert delivered == [["block"]]  # detection delivered
        assert len(client._telemetry_buffer) == 0  # usage dropped, not wedged

    @pytest.mark.asyncio
    async def test_429_rebuffers_instead_of_dropping(self):
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client._telemetry_buffer = [
            TelemetryEvent(event_type="block", category="prompt-injection"),
            TelemetryEvent(event_type="block", category="jailbreak"),
        ]

        mock_response = AsyncMock()
        mock_response.status_code = 429
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client._flush_telemetry()

        assert len(client._telemetry_buffer) == 2  # retained for retry


class TestFlushCancellationSafety:
    @pytest.mark.asyncio
    async def test_cancel_mid_flush_resets_flushing_without_duplicating(self):
        """Cancelling a flush mid-network-IO must reset _flushing (no wedge)
        and must NOT requeue the in-flight batch -- at-most-once, so an
        already-sent billing event is never double-counted on shutdown."""
        import asyncio

        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client._telemetry_buffer = [
            TelemetryEvent(event_type="block", category="prompt-injection"),
            TelemetryEvent(event_type="usage", category="usage"),
        ]

        started = asyncio.Event()

        async def hang(*args, **kwargs):
            started.set()
            await asyncio.sleep(3600)  # never completes; will be cancelled

        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=hang)

        task = asyncio.create_task(client._flush_telemetry())
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert client._flushing is False  # not wedged
        # In-flight batch dropped on hard cancel (at-most-once), not requeued
        assert len(client._telemetry_buffer) == 0

    @pytest.mark.asyncio
    async def test_requeue_on_transient_failure_respects_buffer_cap(self):
        from aiproxyguard.control_plane import TELEMETRY_BUFFER_MAX

        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client._telemetry_buffer = [
            TelemetryEvent(event_type="block", category="x")
            for _ in range(TELEMETRY_BUFFER_MAX)
        ]

        mock_response = AsyncMock()
        mock_response.status_code = 429  # transient -> whole batch requeued
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client._flush_telemetry()

        assert len(client._telemetry_buffer) <= TELEMETRY_BUFFER_MAX

    @pytest.mark.asyncio
    async def test_single_flight_guard_prevents_concurrent_flush(self):
        import asyncio

        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client._telemetry_buffer = [TelemetryEvent(event_type="block", category="x")]

        release = asyncio.Event()
        post_calls = 0

        async def slow_post(*args, **kwargs):
            nonlocal post_calls
            post_calls += 1
            await release.wait()
            resp = AsyncMock()
            resp.status_code = 201
            resp.raise_for_status = MagicMock()
            return resp

        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=slow_post)

        t1 = asyncio.create_task(client._flush_telemetry())
        await asyncio.sleep(0.05)  # let t1 enter the flush and start the post
        # Second flush should no-op via the single-flight guard
        await client._flush_telemetry()
        release.set()
        await t1

        assert post_calls == 1


class TestConfigSectionRegistry:
    """#312: runtime config sections are dispatched through a registry, so a
    new section needs only register_section_handler() -- no dispatcher edits."""

    def _client_with_policy(self):
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        return client

    async def _apply(self, client, cfg: dict):
        """Drive _fetch_and_apply_policy with a mocked policy fetch."""
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value={"name": "p", "version": 1, "config": cfg})
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_response)
        await client._fetch_and_apply_policy()

    @pytest.mark.asyncio
    async def test_registered_section_handler_receives_its_section(self):
        client = self._client_with_policy()
        seen = {}
        client.register_section_handler("routing", lambda c: seen.update(c))

        await self._apply(client, {"routing": {"enabled": True, "rules": [1, 2]}})

        assert seen == {"enabled": True, "rules": [1, 2]}

    @pytest.mark.asyncio
    async def test_new_section_needs_no_dispatcher_change(self):
        """A brand-new section name works purely via registration."""
        client = self._client_with_policy()
        calls = []
        for name in ("cache", "budget", "cost_optimization"):
            client.register_section_handler(name, lambda c, n=name: calls.append((n, c)))

        await self._apply(client, {
            "cache": {"ttl": 60},
            "budget": {"daily": 1000},
            "cost_optimization": {"mode": "aggressive"},
        })

        assert sorted(n for n, _ in calls) == ["budget", "cache", "cost_optimization"]

    @pytest.mark.asyncio
    async def test_one_bad_section_does_not_abort_others(self):
        client = self._client_with_policy()
        applied = []

        def boom(_):
            raise ValueError("bad routing config")

        client.register_section_handler("routing", boom)
        client.register_section_handler("logging", lambda c: applied.append("logging"))

        # Must not raise, and logging must still be applied despite routing failing
        await self._apply(client, {"routing": {"x": 1}, "logging": {"level": "debug"}})

        assert applied == ["logging"]

    @pytest.mark.asyncio
    async def test_unknown_section_warns(self, caplog):
        import logging as _logging

        client = self._client_with_policy()
        with caplog.at_level(_logging.WARNING):
            await self._apply(client, {"totally_unknown_section": {"x": 1}})

        assert any("unrecognized" in r.message.lower() for r in caplog.records)

    @pytest.mark.asyncio
    async def test_boot_only_section_ignored_without_warning(self, caplog):
        import logging as _logging

        client = self._client_with_policy()
        with caplog.at_level(_logging.WARNING):
            await self._apply(client, {"upstreams": {"openai": {"url": "x"}}, "tls": {"enabled": True}})

        assert not any("unrecognized" in r.message.lower() for r in caplog.records)

    @pytest.mark.asyncio
    async def test_typed_setters_register_into_registry(self):
        client = self._client_with_policy()
        client.set_logging_update_callback(lambda c: None)
        client.set_scanner_update_callback(lambda c: None)
        client.set_ml_config_update_callback(lambda c: None)
        client.set_security_update_callback(lambda c: None)

        assert set(client._section_handlers) == {"logging", "scanner", "ml_classifier", "security"}


class TestUnconsumedPolicyKeyDrift:
    @pytest.mark.asyncio
    async def test_top_level_default_action_warns_as_drift(self, caplog):
        """A top-level default_action is NOT consumed by the translation, so it
        must surface as an unrecognized-section warning, not be silently dropped."""
        import logging as _logging

        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        client.set_policy_update_callback(lambda c: None)

        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value={
            "name": "p", "version": 1,
            "config": {"detection": {"prompt-injection": {"enabled": True, "action": "block"}},
                       "default_action": "warn"},
        })
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_response)

        with caplog.at_level(_logging.WARNING):
            await client._fetch_and_apply_policy()

        assert any("default_action" in str(r.__dict__.get("section", "")) for r in caplog.records)


class TestModelSyncOrdering:
    """#69: the model-sync-begin callback (which resets the scanner's
    highest-tier-wins state) must fire before the first ML model is applied, in
    BOTH the online and offline sync paths. Otherwise a tier downgrade would not
    take effect, or a stale higher tier could keep clobbering the entitled one.
    """

    @pytest.mark.asyncio
    async def test_online_sync_begin_fires_before_first_model(self, monkeypatch):
        client = ControlPlaneClient(MockControlPlaneConfig())
        client._tier = "enterprise"

        order: list = []
        client.set_model_sync_begin_callback(lambda: order.append("begin"))
        client.set_ml_model_callback(lambda data, cfg: order.append(("model", cfg["tier"])))

        # Manifest with two encrypted bundles in the prod-observed order.
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value={
            "version": "v1",
            "bundles": [
                {"id": "b-free", "is_encrypted": True, "tier": "free"},
                {"id": "b-ent", "is_encrypted": True, "tier": "enterprise"},
            ],
        })
        client._client = MagicMock()
        client._client.get = AsyncMock(return_value=resp)
        client._manifest_verifier = MagicMock()
        client._manifest_verifier.verify_manifest = MagicMock(
            return_value=MagicMock(valid=True, sequence=1)
        )

        async def fake_fetch(bundle_id, bundle_info, *a, **k):
            return {
                "content_info": {"bundle_id": bundle_id},
                "model_data": b"MODEL",
                "model_format": "onnx",
                "model_config": {"model_id": bundle_id, "model_version": "1"},
            }

        monkeypatch.setattr(client, "_fetch_encrypted_bundle", fake_fetch)
        monkeypatch.setattr(
            "aiproxyguard.signatures.loader.parse_bundles_to_bundle_set",
            lambda bc, lic: MagicMock(
                get_active_signatures=lambda: MagicMock(signatures=[]),
                get_expiring_soon=lambda **k: [],
                active_signatures_count=0,
                total_signatures=0,
            ),
        )
        monkeypatch.setattr("aiproxyguard.signatures.cache.clear_expired_cache", lambda: None)

        await client._fetch_and_apply_signatures()

        assert order, "no callbacks fired"
        assert order[0] == "begin", f"begin must fire first, got {order}"
        models = [x for x in order if x != "begin"]
        assert ("model", "free") in models
        assert ("model", "enterprise") in models
        assert order.count("begin") == 1

    @pytest.mark.asyncio
    async def test_offline_sync_begin_fires_before_first_model(self, monkeypatch):
        import aiproxyguard.control_plane as cp_mod

        client = ControlPlaneClient(MockControlPlaneConfig())

        order: list = []
        client.set_model_sync_begin_callback(lambda: order.append("begin"))
        client.set_ml_model_callback(lambda data, cfg: order.append(("model", cfg["tier"])))

        monkeypatch.setattr(
            "aiproxyguard.signatures.cache.list_cached_bundles",
            lambda: ["b-free", "b-ent"],
        )

        def fake_load(bundle_id):
            tier = "enterprise" if "ent" in bundle_id else "free"
            return (b"enc", {"dek": "k", "tier": tier, "bundle_version": "1"})

        monkeypatch.setattr("aiproxyguard.signatures.cache.load_bundle_cache", fake_load)

        class FakeLicense:
            bound_instance_id = None
            dek = "k"

        monkeypatch.setattr(
            "aiproxyguard.crypto.license.parse_license", lambda ld: FakeLicense()
        )
        monkeypatch.setattr(
            "aiproxyguard.crypto.license.decrypt_content",
            lambda *a, **k: b"\x1f\x8bmodelblob",
        )

        class FakeContent:
            yaml_content = "rules: []"
            model_data = b"MODEL"
            model_format = "onnx"
            model_config = {"model_id": "m", "model_version": "1"}

        monkeypatch.setattr(cp_mod, "_extract_bundle_content", lambda d: FakeContent())
        monkeypatch.setattr(
            "aiproxyguard.signatures.loader.parse_bundles_to_bundle_set",
            lambda bc, lic: MagicMock(
                get_active_signatures=lambda: MagicMock(signatures=[]),
                active_signatures_count=0,
            ),
        )

        await client._load_signatures_from_cache()

        assert order, "no callbacks fired"
        assert order[0] == "begin", f"begin must fire first, got {order}"
        models = [x for x in order if x != "begin"]
        assert ("model", "free") in models
        assert ("model", "enterprise") in models
        assert order.count("begin") == 1


class TestScalarScanToggles:
    """scan_request/scan_response are scalar booleans, and `version` is
    metadata. The dispatcher must apply falsy scalars (not skip them) and not
    warn on version."""

    def _client(self):
        config = MockControlPlaneConfig()
        client = ControlPlaneClient(config)
        client._registered = True
        return client

    async def _apply(self, client, cfg):
        resp = AsyncMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value={"name": "p", "version": 1, "config": cfg})
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=resp)
        await client._fetch_and_apply_policy()

    @pytest.mark.asyncio
    async def test_scalar_false_section_is_applied_not_skipped(self):
        client = self._client()
        seen = []
        client.register_section_handler("scan_request", lambda v: seen.append(v))
        await self._apply(client, {"scan_request": False})
        assert seen == [False]  # falsy value still dispatched

    @pytest.mark.asyncio
    async def test_scalar_true_section_applied(self):
        client = self._client()
        seen = []
        client.register_section_handler("scan_response", lambda v: seen.append(v))
        await self._apply(client, {"scan_response": True})
        assert seen == [True]

    @pytest.mark.asyncio
    async def test_absent_section_not_dispatched(self):
        client = self._client()
        seen = []
        client.register_section_handler("scan_request", lambda v: seen.append(v))
        await self._apply(client, {"detection": {}})
        assert seen == []  # not present -> handler not called

    @pytest.mark.asyncio
    async def test_version_metadata_does_not_warn(self, caplog):
        import logging as _logging
        client = self._client()
        with caplog.at_level(_logging.WARNING):
            await self._apply(client, {"version": 1, "detection": {}})
        assert not any("unrecognized" in r.message.lower() for r in caplog.records)
