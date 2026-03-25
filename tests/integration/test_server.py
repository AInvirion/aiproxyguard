"""Integration tests for HTTP server."""

import pytest
from aiohttp.test_utils import TestClient, TestServer

from aiproxyguard.server import create_app
from aiproxyguard.config import Config, ServerConfig, UpstreamConfig, ScannerConfig


@pytest.fixture
def config() -> Config:
    """Test configuration."""
    return Config(
        server=ServerConfig(host="127.0.0.1", port=8080),
        upstreams={
            "mock": UpstreamConfig(url="http://127.0.0.1:9999", auth_header="Authorization"),
        },
        scanner=ScannerConfig(enabled=False),
    )


@pytest.fixture
async def client(config: Config) -> TestClient:
    """Create test client."""
    app = create_app(config)
    async with TestClient(TestServer(app)) as test_client:
        yield test_client


async def test_health_endpoint(client: TestClient) -> None:
    """Health endpoint returns 200."""
    resp = await client.get("/healthz")
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "healthy"


async def test_readiness_endpoint(client: TestClient) -> None:
    """Readiness endpoint returns 200."""
    resp = await client.get("/readyz")
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "ready"


async def test_metrics_endpoint(client: TestClient) -> None:
    """Metrics endpoint returns Prometheus format."""
    resp = await client.get("/metrics")
    assert resp.status == 200
    text = await resp.text()
    assert "aiproxyguard" in text


async def test_unknown_provider_returns_404(client: TestClient) -> None:
    """Unknown provider returns 404."""
    resp = await client.get("/unknown/v1/models")
    assert resp.status == 404
