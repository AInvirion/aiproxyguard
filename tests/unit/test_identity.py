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

"""Tests for client identity resolution."""

import pytest

from aiproxyguard.identity import IdentityResolver


class TestIdentityResolver:
    """Test client identity resolution."""

    def test_resolve_from_header(self) -> None:
        """Resolve identity from header."""
        resolver = IdentityResolver(method="header", header_name="X-Client-ID")
        headers = {"X-Client-ID": "my-app"}

        identity = resolver.resolve(headers)

        assert identity == "my-app"

    def test_resolve_from_header_fallback(self) -> None:
        """Fall back to secondary header."""
        resolver = IdentityResolver(
            method="header",
            header_name="X-Client-ID",
            fallback_header="X-Forwarded-For"
        )
        headers = {"X-Forwarded-For": "192.168.1.1"}

        identity = resolver.resolve(headers)

        assert identity == "192.168.1.1"

    def test_resolve_unknown(self) -> None:
        """Unknown identity when no headers match."""
        resolver = IdentityResolver(method="header", header_name="X-Client-ID")
        headers = {}

        identity = resolver.resolve(headers)

        assert identity == "unknown"

    def test_resolve_from_ip(self) -> None:
        """Resolve identity from IP."""
        resolver = IdentityResolver(method="ip")

        identity = resolver.resolve({}, remote_addr="10.0.0.1")

        assert identity == "10.0.0.1"

    def test_invalid_method_raises(self) -> None:
        """Invalid method raises ValueError."""
        with pytest.raises(ValueError, match="Invalid method"):
            IdentityResolver(method="invalid")

    def test_resolve_from_token_hashed(self) -> None:
        """Token resolution with hashing."""
        resolver = IdentityResolver(method="token", hash_token=True)
        headers = {"Authorization": "Bearer secret-token-123"}

        identity = resolver.resolve(headers)

        assert identity != "secret-token-123"  # Hashed, not raw
        assert len(identity) == 32  # 32 hex chars

    def test_resolve_from_token_raw(self) -> None:
        """Token resolution without hashing."""
        resolver = IdentityResolver(method="token", hash_token=False)
        headers = {"Authorization": "Bearer my-api-key"}

        identity = resolver.resolve(headers)

        assert identity == "my-api-key"

    def test_resolve_ip_with_xff(self) -> None:
        """IP resolution trusting X-Forwarded-For."""
        resolver = IdentityResolver(method="ip", trust_xff=True)
        headers = {"X-Forwarded-For": "203.0.113.50, 70.41.3.18"}

        identity = resolver.resolve(headers, remote_addr="10.0.0.1")

        assert identity == "203.0.113.50"  # First IP from XFF
