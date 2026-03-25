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

"""Tests for request router."""

import pytest
from aiproxyguard.router import Router, RouteMatch
from aiproxyguard.config import UpstreamConfig


class TestRouter:
    """Test path-based routing."""

    @pytest.fixture
    def upstreams(self) -> dict[str, UpstreamConfig]:
        """Test upstreams."""
        return {
            "openai": UpstreamConfig(url="https://api.openai.com", auth_header="Authorization", timeout=30),
            "anthropic": UpstreamConfig(url="https://api.anthropic.com", auth_header="x-api-key"),
            "ollama": UpstreamConfig(url="http://localhost:11434", auth_header=None),
        }

    def test_route_openai(self, upstreams: dict[str, UpstreamConfig]) -> None:
        """Route OpenAI requests."""
        router = Router(upstreams)
        match = router.match("/openai/v1/chat/completions")

        assert match is not None
        assert match.upstream_url == "https://api.openai.com/v1/chat/completions"
        assert match.auth_header == "Authorization"
        assert match.timeout == 30

    def test_route_anthropic(self, upstreams: dict[str, UpstreamConfig]) -> None:
        """Route Anthropic requests."""
        router = Router(upstreams)
        match = router.match("/anthropic/v1/messages")

        assert match is not None
        assert match.upstream_url == "https://api.anthropic.com/v1/messages"

    def test_route_not_found(self, upstreams: dict[str, UpstreamConfig]) -> None:
        """Unknown path returns None."""
        router = Router(upstreams)
        match = router.match("/unknown/endpoint")

        assert match is None

    def test_route_preserves_query_string(self, upstreams: dict[str, UpstreamConfig]) -> None:
        """Query strings are preserved."""
        router = Router(upstreams)
        match = router.match("/openai/v1/models?limit=10")

        assert match is not None
        assert match.upstream_url == "https://api.openai.com/v1/models?limit=10"
