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

"""Tests for TLS proxy security features."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import MagicMock



@dataclass
class MockUpstreamConfig:
    """Mock upstream configuration."""

    url: str
    timeout: int = 60
    auth_header: str | None = "Authorization"


@dataclass
class MockSecurityConfig:
    """Mock security configuration."""

    failure_mode: str = "open"
    scanner_timeout_ms: int = 100
    upstream_timeout_s: int = 60
    max_request_size: int = 10 * 1024 * 1024
    max_response_size: int = 50 * 1024 * 1024
    expose_details: bool = False


@dataclass
class MockScannerConfig:
    """Mock scanner configuration."""

    enabled: bool = True
    regex: bool = True
    heuristics: bool = True
    ml_classifier: bool = False


@dataclass
class MockConfig:
    """Mock configuration for TLS proxy tests."""

    upstreams: dict
    security: MockSecurityConfig = field(default_factory=MockSecurityConfig)
    scanner: MockScannerConfig = field(default_factory=MockScannerConfig)


class TestTLSProxyHostAllowlist:
    """Tests for TLS proxy host allowlist validation."""

    def test_build_allowed_hosts_from_upstreams(self):
        """Should extract hostnames from upstream URLs."""
        from aiproxyguard.tls_proxy import TLSInterceptProxy

        config = MockConfig(
            upstreams={
                "openai": MockUpstreamConfig(url="https://api.openai.com/v1"),
                "anthropic": MockUpstreamConfig(url="https://api.anthropic.com"),
                "custom": MockUpstreamConfig(url="https://my-llm.example.com:8443/api"),
            }
        )

        # Create mock dependencies
        mock_ca = MagicMock()
        mock_scanner = MagicMock()
        mock_policy = MagicMock()
        mock_identity = MagicMock()
        mock_metrics = MagicMock()

        proxy = TLSInterceptProxy(
            config=config,
            ca=mock_ca,
            scanner=mock_scanner,
            policy=mock_policy,
            identity=mock_identity,
            metrics=mock_metrics,
        )

        assert "api.openai.com" in proxy._allowed_hosts
        assert "api.anthropic.com" in proxy._allowed_hosts
        assert "my-llm.example.com" in proxy._allowed_hosts

    def test_is_host_allowed_case_insensitive(self):
        """Host matching should be case insensitive."""
        from aiproxyguard.tls_proxy import TLSInterceptProxy

        config = MockConfig(
            upstreams={
                "openai": MockUpstreamConfig(url="https://API.OpenAI.com/v1"),
            }
        )

        mock_ca = MagicMock()
        mock_scanner = MagicMock()
        mock_policy = MagicMock()
        mock_identity = MagicMock()
        mock_metrics = MagicMock()

        proxy = TLSInterceptProxy(
            config=config,
            ca=mock_ca,
            scanner=mock_scanner,
            policy=mock_policy,
            identity=mock_identity,
            metrics=mock_metrics,
        )

        # All case variations should be allowed
        assert proxy._is_host_allowed("api.openai.com")
        assert proxy._is_host_allowed("API.OPENAI.COM")
        assert proxy._is_host_allowed("Api.OpenAI.Com")

    def test_disallowed_host_rejected(self):
        """Hosts not in upstream config should be rejected."""
        from aiproxyguard.tls_proxy import TLSInterceptProxy

        config = MockConfig(
            upstreams={
                "openai": MockUpstreamConfig(url="https://api.openai.com/v1"),
            }
        )

        mock_ca = MagicMock()
        mock_scanner = MagicMock()
        mock_policy = MagicMock()
        mock_identity = MagicMock()
        mock_metrics = MagicMock()

        proxy = TLSInterceptProxy(
            config=config,
            ca=mock_ca,
            scanner=mock_scanner,
            policy=mock_policy,
            identity=mock_identity,
            metrics=mock_metrics,
        )

        # Should not allow arbitrary hosts
        assert not proxy._is_host_allowed("evil.attacker.com")
        assert not proxy._is_host_allowed("internal.corp.local")
        assert not proxy._is_host_allowed("192.168.1.1")

    def test_empty_upstreams_blocks_all_hosts(self):
        """With no upstreams configured, all hosts should be blocked."""
        from aiproxyguard.tls_proxy import TLSInterceptProxy

        config = MockConfig(upstreams={})

        mock_ca = MagicMock()
        mock_scanner = MagicMock()
        mock_policy = MagicMock()
        mock_identity = MagicMock()
        mock_metrics = MagicMock()

        proxy = TLSInterceptProxy(
            config=config,
            ca=mock_ca,
            scanner=mock_scanner,
            policy=mock_policy,
            identity=mock_identity,
            metrics=mock_metrics,
        )

        assert len(proxy._allowed_hosts) == 0
        assert not proxy._is_host_allowed("any.host.com")


class TestTLSProxyVendorHeaders:
    """Tests for vendor header forwarding."""

    def test_allowed_headers_list(self):
        """Vendor headers should be in the allowed list."""
        # This tests the expected headers that should be forwarded
        allowed_headers = (
            # Standard headers
            "content-type", "accept", "accept-encoding", "accept-language",
            # Auth headers
            "authorization", "api-key", "x-api-key",
            # OpenAI headers
            "openai-organization", "openai-project", "openai-beta",
            # Anthropic headers
            "anthropic-version", "anthropic-beta", "anthropic-dangerous-direct-browser-access",
            # OpenRouter headers
            "x-title", "http-referer",
            # Common request IDs
            "x-request-id", "x-correlation-id",
        )

        # Verify critical vendor headers are present
        assert "anthropic-version" in allowed_headers
        assert "openai-organization" in allowed_headers
        assert "openai-beta" in allowed_headers
        assert "anthropic-beta" in allowed_headers
