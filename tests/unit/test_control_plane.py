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
