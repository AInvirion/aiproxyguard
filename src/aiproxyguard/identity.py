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

"""Client identity resolution."""

from __future__ import annotations

import hashlib
from typing import Any


class IdentityResolver:
    """Resolve client identity from request context."""

    def __init__(
        self,
        method: str = "header",
        header_name: str = "X-Client-ID",
        fallback_header: str | None = None,
        trust_xff: bool = False,
        hash_token: bool = True,
    ) -> None:
        """Initialize resolver.

        Args:
            method: Resolution method (header, ip, token, mtls)
            header_name: Primary header to check
            fallback_header: Secondary header if primary not found
            trust_xff: Trust X-Forwarded-For header for IP resolution
            hash_token: Hash tokens for privacy

        Raises:
            ValueError: If method is not one of the valid methods.
        """
        VALID_METHODS = {"header", "ip", "token", "mtls"}
        if method not in VALID_METHODS:
            raise ValueError(
                f"Invalid method: {method}. Must be one of: {VALID_METHODS}"
            )

        self.method = method
        self.header_name = header_name
        self.fallback_header = fallback_header
        self.trust_xff = trust_xff
        self.hash_token = hash_token

    def resolve(
        self,
        headers: dict[str, Any],
        remote_addr: str | None = None,
        client_cert_cn: str | None = None,
    ) -> str:
        """Resolve client identity from request context."""
        if self.method == "header":
            return self._resolve_header(headers)
        elif self.method == "ip":
            return self._resolve_ip(headers, remote_addr)
        elif self.method == "token":
            return self._resolve_token(headers)
        elif self.method == "mtls":
            return client_cert_cn or "unknown"
        else:
            return "unknown"

    def _resolve_header(self, headers: dict[str, Any]) -> str:
        """Resolve from header."""
        # Case-insensitive header lookup
        headers_lower = {k.lower(): v for k, v in headers.items()}

        value = headers_lower.get(self.header_name.lower())
        if value:
            return str(value)

        if self.fallback_header:
            value = headers_lower.get(self.fallback_header.lower())
            if value:
                # Take first IP if comma-separated (XFF format)
                return str(value).split(",")[0].strip()

        return "unknown"

    def _resolve_ip(self, headers: dict[str, Any], remote_addr: str | None) -> str:
        """Resolve from IP address."""
        if self.trust_xff:
            headers_lower = {k.lower(): v for k, v in headers.items()}
            xff = headers_lower.get("x-forwarded-for")
            if xff:
                return str(xff).split(",")[0].strip()

        return remote_addr or "unknown"

    def _resolve_token(self, headers: dict[str, Any]) -> str:
        """Resolve from authorization token."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        auth = headers_lower.get("authorization", "")

        if not auth:
            return "unknown"

        # Extract token
        if auth.lower().startswith("bearer "):
            token = auth[7:]
        else:
            token = auth

        if self.hash_token:
            return hashlib.sha256(token.encode()).hexdigest()[:32]

        return token
