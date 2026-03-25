"""Path-based request routing to upstream LLM providers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiproxyguard.config import UpstreamConfig


@dataclass
class RouteMatch:
    """A matched route."""

    provider: str
    upstream_url: str
    auth_header: str | None
    timeout: int


class Router:
    """Route requests to upstream providers based on path prefix."""

    def __init__(self, upstreams: dict[str, UpstreamConfig]) -> None:
        """Initialize router with upstream configuration."""
        self._upstreams = upstreams

    def match(self, path: str) -> RouteMatch | None:
        """Match a request path to an upstream.

        Path format: /{provider}/{rest_of_path}
        Example: /openai/v1/chat/completions -> https://api.openai.com/v1/chat/completions
        """
        # Parse path
        parts = path.split("/", 2)
        if len(parts) < 2:
            return None

        # Extract provider and remaining path
        provider = parts[1].lower()
        remaining = "/" + parts[2] if len(parts) > 2 else "/"

        # Look up upstream
        upstream = self._upstreams.get(provider)
        if not upstream:
            return None

        # Build upstream URL
        base = upstream.url.rstrip("/")
        upstream_url = base + remaining

        return RouteMatch(
            provider=provider,
            upstream_url=upstream_url,
            auth_header=upstream.auth_header,
            timeout=upstream.timeout,
        )

    def list_providers(self) -> list[str]:
        """List available providers."""
        return list(self._upstreams.keys())
