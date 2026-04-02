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


async def test_root_endpoint(client: TestClient) -> None:
    """Root endpoint returns service info."""
    resp = await client.get("/")
    assert resp.status == 200
    data = await resp.json()
    assert data["service"] == "AIProxyGuard"
    assert "version" in data


async def test_unknown_provider_returns_404(client: TestClient) -> None:
    """Unknown provider returns 404."""
    resp = await client.get("/unknown/v1/models")
    assert resp.status == 404


# /check endpoint tests


@pytest.fixture
def config_with_scanner() -> Config:
    """Test configuration with scanner enabled."""
    return Config(
        server=ServerConfig(host="127.0.0.1", port=8080),
        upstreams={
            "mock": UpstreamConfig(url="http://127.0.0.1:9999", auth_header="Authorization"),
        },
        scanner=ScannerConfig(enabled=True, regex=True, heuristics=True),
    )


@pytest.fixture
async def client_with_scanner(config_with_scanner: Config) -> TestClient:
    """Create test client with scanner enabled."""
    app = create_app(config_with_scanner)
    async with TestClient(TestServer(app)) as test_client:
        yield test_client


async def test_check_endpoint_allows_safe_text(client_with_scanner: TestClient) -> None:
    """Check endpoint allows safe text."""
    resp = await client_with_scanner.post("/check", json={"text": "Hello, how are you?"})
    assert resp.status == 200
    data = await resp.json()
    assert data["action"] == "allow"


async def test_check_endpoint_returns_required_fields(client_with_scanner: TestClient) -> None:
    """Check endpoint returns all required fields."""
    resp = await client_with_scanner.post("/check", json={"text": "Hello"})
    assert resp.status == 200
    data = await resp.json()
    assert "action" in data
    assert "category" in data
    assert "signature_name" in data
    assert "confidence" in data
    # signature_id and details are intentionally not exposed to prevent reverse engineering
    assert "signature_id" not in data
    assert "details" not in data


async def test_check_endpoint_rejects_missing_text(client_with_scanner: TestClient) -> None:
    """Check endpoint rejects request without text field."""
    resp = await client_with_scanner.post("/check", json={})
    assert resp.status == 400
    data = await resp.json()
    assert data["error"]["type"] == "invalid_request"


async def test_check_endpoint_rejects_invalid_json(client_with_scanner: TestClient) -> None:
    """Check endpoint rejects invalid JSON."""
    resp = await client_with_scanner.post(
        "/check",
        data="not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 400
    data = await resp.json()
    assert data["error"]["type"] == "invalid_json"


async def test_check_endpoint_rejects_non_string_text(client_with_scanner: TestClient) -> None:
    """Check endpoint rejects non-string text field."""
    resp = await client_with_scanner.post("/check", json={"text": 123})
    assert resp.status == 400
    data = await resp.json()
    assert data["error"]["type"] == "invalid_request"


async def test_check_endpoint_rejects_non_object_body(client_with_scanner: TestClient) -> None:
    """Check endpoint rejects JSON that is not an object (e.g., array, string)."""
    # Test with array
    resp = await client_with_scanner.post("/check", json=["hello"])
    assert resp.status == 400
    data = await resp.json()
    assert data["error"]["type"] == "invalid_request"
    assert "object" in data["error"]["message"].lower()

    # Test with string
    resp = await client_with_scanner.post("/check", json="hello")
    assert resp.status == 400

    # Test with number
    resp = await client_with_scanner.post("/check", json=123)
    assert resp.status == 400
