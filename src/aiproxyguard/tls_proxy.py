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

"""TLS-intercepting proxy handler using asyncio.

This module provides a CONNECT-based forward proxy that intercepts TLS
connections, allowing inspection of HTTPS traffic to upstream LLM providers.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import aiohttp

if TYPE_CHECKING:
    from aiproxyguard.config import Config
    from aiproxyguard.tls import CertificateAuthority

from aiproxyguard.logging import get_logger
from aiproxyguard.metrics import MetricsCollector
from aiproxyguard.pipeline import PipelineRequest, RequestPipeline, UpstreamTarget
from aiproxyguard.policy import PolicyEngine
from aiproxyguard.scanner.pipeline import ScannerPipeline
from aiproxyguard.identity import IdentityResolver

logger = get_logger("tls_proxy")

_STATUS_REASONS = {
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    413: "Payload Too Large",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


def _status_reason(status: int) -> str:
    return _STATUS_REASONS.get(status, "Error")


@dataclass
class TLSConnection:
    """Represents a TLS connection being intercepted."""

    hostname: str
    port: int
    client_reader: asyncio.StreamReader
    client_writer: asyncio.StreamWriter
    ssl_context: ssl.SSLContext


class TLSInterceptProxy:
    """TLS-intercepting forward proxy.

    This proxy handles CONNECT requests, performs TLS interception using
    dynamically generated certificates, and forwards decrypted traffic
    through the scanner pipeline.
    """

    def __init__(
        self,
        config: "Config",
        ca: "CertificateAuthority",
        scanner: ScannerPipeline,
        policy: PolicyEngine,
        identity: IdentityResolver,
        metrics: MetricsCollector,
    ) -> None:
        self._config = config
        self._ca = ca
        self._scanner = scanner
        self._policy = policy
        self._identity = identity
        self._metrics = metrics
        self._http_session: aiohttp.ClientSession | None = None
        # Map allowed hostnames to their upstream config (provider name, config)
        self._host_to_upstream: dict[str, tuple[str, object]] = self._build_host_map(config)
        self._allowed_hosts: set[str] = set(self._host_to_upstream)
        # Same response cache + cost-optimization mutators as the HTTP path.
        from aiproxyguard.server import (
            _build_response_cache,
            register_cost_optimization_mutators,
        )

        self._pipeline = RequestPipeline(
            config=config,
            scanner=scanner,
            policy=policy,
            metrics=metrics,
            session_getter=self._get_session,
            cache=_build_response_cache(config),
        )
        register_cost_optimization_mutators(self._pipeline, config)

    def _build_host_map(self, config: "Config") -> dict[str, tuple[str, object]]:
        """Map upstream hostnames to (provider name, upstream config)."""
        host_map: dict[str, tuple[str, object]] = {}
        for provider, upstream in config.upstreams.items():
            parsed = urlparse(upstream.url)
            if parsed.hostname:
                host_map[parsed.hostname.lower()] = (provider, upstream)
        return host_map

    def _get_session(self) -> aiohttp.ClientSession:
        if self._http_session is None:
            self._http_session = aiohttp.ClientSession()
        return self._http_session

    def _resolve_target(self, host: str, port: int, path: str) -> UpstreamTarget:
        """Resolve the upstream target, using per-upstream config when the host matches."""
        provider = host
        auth_header = None
        timeout = float(self._config.security.upstream_timeout_s)
        match = self._host_to_upstream.get(host.lower())
        if match:
            provider, upstream = match
            auth_header = upstream.auth_header
            timeout = float(upstream.timeout)
        return UpstreamTarget(
            provider=provider,
            url=f"https://{host}:{port}{path}",
            auth_header=auth_header,
            timeout=timeout,
        )

    def _is_host_allowed(self, host: str) -> bool:
        """Check if host is in the allowlist of configured upstreams."""
        return host.lower() in self._allowed_hosts

    async def start(self, host: str, port: int) -> asyncio.Server:
        """Start the TLS intercepting proxy server."""
        self._http_session = aiohttp.ClientSession()
        server = await asyncio.start_server(
            self._handle_connection,
            host,
            port,
        )
        logger.info(
            "TLS intercept proxy started",
            extra={"host": host, "port": port},
        )
        return server

    async def stop(self) -> None:
        """Stop the proxy and cleanup resources."""
        if self._http_session:
            await self._http_session.close()
            self._http_session = None

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle incoming client connection."""
        peername = writer.get_extra_info("peername")
        try:
            # Read the initial request line
            request_line = await reader.readline()
            if not request_line:
                return

            request_str = request_line.decode("utf-8", errors="replace").strip()
            parts = request_str.split()

            if len(parts) < 3:
                await self._send_error(writer, 400, "Bad Request")
                return

            method, target, _version = parts[0], parts[1], parts[2]

            # Read headers
            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                try:
                    key, value = line.decode("utf-8").strip().split(":", 1)
                    headers[key.strip().lower()] = value.strip()
                except ValueError:
                    continue

            if method == "CONNECT":
                await self._handle_connect(reader, writer, target, headers, peername)
            else:
                # For non-CONNECT requests, proxy directly
                await self._handle_http(reader, writer, method, target, headers, peername)

        except Exception as e:
            logger.error(f"Connection handler error: {e}", extra={"peer": peername})
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
        headers: dict[str, str],
        peername: tuple[str, int] | None,
    ) -> None:
        """Handle CONNECT request for TLS interception."""
        # Parse target (host:port)
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        else:
            host = target
            port = 443

        logger.debug(f"CONNECT request for {host}:{port}", extra={"peer": peername})

        # Validate host is in allowlist (CRITICAL: prevents open proxy abuse)
        if not self._is_host_allowed(host):
            logger.warning(
                "CONNECT to disallowed host rejected",
                extra={"host": host, "port": port, "peer": peername},
            )
            await self._send_error(writer, 403, "Forbidden: host not in allowlist")
            return

        # Send 200 Connection Established
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Generate certificate for this host and create SSL context
        try:
            cert_pem, key_pem = self._ca.generate_certificate(host)
        except Exception as e:
            logger.error(f"Failed to generate certificate for {host}: {e}")
            return

        # Create server-side SSL context
        import tempfile
        import os

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Write cert and key to temp files
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cert_file:
            cert_file.write(cert_pem)
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as key_file:
            key_file.write(key_pem)
            key_path = key_file.name

        try:
            ssl_context.load_cert_chain(cert_path, key_path)
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

        # Wrap the connection with TLS using start_tls (Python 3.11+)
        try:
            await asyncio.wait_for(
                writer.start_tls(ssl_context),
                timeout=10.0,
            )
            # After start_tls, the reader/writer continue to work with TLS

        except Exception as e:
            logger.error(f"TLS handshake failed for {host}: {e}")
            return

        # Now handle the decrypted HTTP traffic
        await self._handle_tls_connection(
            reader,
            writer,
            host,
            port,
            headers,
            peername,
        )

    async def _handle_tls_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        upstream_host: str,
        upstream_port: int,
        original_headers: dict[str, str],
        peername: tuple[str, int] | None,
    ) -> None:
        """Handle decrypted TLS connection."""
        while True:
            # Read HTTP request from client
            try:
                request_line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=60.0,
                )
                if not request_line:
                    break

                request_str = request_line.decode("utf-8", errors="replace").strip()
                if not request_str:
                    break

                parts = request_str.split()
                if len(parts) < 3:
                    break

                method, path, _version = parts[0], parts[1], parts[2]

                # Read headers
                headers: dict[str, str] = {}
                raw_headers: list[tuple[str, str]] = []
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                    try:
                        key, value = line.decode("utf-8").strip().split(":", 1)
                        headers[key.strip().lower()] = value.strip()
                        raw_headers.append((key.strip(), value.strip()))
                    except ValueError:
                        continue

                # Read body if present (with size limit check)
                body = b""
                content_length = headers.get("content-length")
                if content_length:
                    content_len_int = int(content_length)
                    # Check request size limit before reading
                    if content_len_int > self._config.security.max_request_size:
                        logger.warning(
                            "Request body exceeds size limit",
                            extra={
                                "content_length": content_len_int,
                                "limit": self._config.security.max_request_size,
                            },
                        )
                        await self._send_json_response(
                            writer,
                            413,
                            {"error": {"type": "payload_too_large", "message": "Request body exceeds size limit"}},
                        )
                        continue
                    body = await reader.readexactly(content_len_int)

                # Process through scanner and forward
                await self._forward_request(
                    writer,
                    method,
                    path,
                    headers,
                    raw_headers,
                    body,
                    upstream_host,
                    upstream_port,
                    peername,
                )

            except asyncio.TimeoutError:
                break
            except asyncio.IncompleteReadError:
                break
            except Exception as e:
                logger.error(f"Error handling TLS connection: {e}")
                break

    async def _forward_request(
        self,
        writer: asyncio.StreamWriter,
        method: str,
        path: str,
        headers: dict[str, str],
        raw_headers: list[tuple[str, str]],
        body: bytes,
        upstream_host: str,
        upstream_port: int,
        peername: tuple[str, int] | None,
    ) -> None:
        """Forward request through the shared pipeline and write the result."""
        client_ip = peername[0] if peername else "unknown"

        # Resolve identity
        headers_dict = {k: v for k, v in raw_headers}
        client_id = self._identity.resolve(headers_dict, client_ip)

        result = await self._pipeline.process(PipelineRequest(
            method=method,
            path=path,
            headers=headers,
            body=body,
            client_id=client_id,
            target=self._resolve_target(upstream_host, upstream_port, path),
        ))

        # Send response back to client
        reason = result.reason or _status_reason(result.status)
        writer.write(f"HTTP/1.1 {result.status} {reason}\r\n".encode())
        for header, value in result.headers.items():
            writer.write(f"{header}: {value}\r\n".encode())
        writer.write(f"content-length: {len(result.body)}\r\n".encode())
        writer.write(b"\r\n")
        writer.write(result.body)
        await writer.drain()

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        target: str,
        headers: dict[str, str],
        peername: tuple[str, int] | None,
    ) -> None:
        """Handle plain HTTP request (non-CONNECT)."""
        # Parse target URL
        parsed = urlparse(target)
        host = parsed.hostname or headers.get("host", "")
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        # Validate host is in allowlist (same rule as CONNECT - prevents open proxy abuse)
        if not self._is_host_allowed(host):
            logger.warning(
                "HTTP request to disallowed host rejected",
                extra={"host": host, "port": port, "peer": peername},
            )
            await self._send_error(writer, 403, "Forbidden: host not in allowlist")
            return

        # Read body if present
        body = b""
        content_length = headers.get("content-length")
        if content_length:
            body = await reader.readexactly(int(content_length))

        # For HTTP, forward directly (no TLS interception needed)
        await self._forward_request(
            writer,
            method,
            path,
            headers,
            list(headers.items()),
            body,
            host,
            port,
            peername,
        )

    async def _send_error(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        message: str,
    ) -> None:
        """Send an HTTP error response."""
        response = f"HTTP/1.1 {status} {message}\r\n"
        response += "Content-Type: text/plain\r\n"
        response += f"Content-Length: {len(message)}\r\n"
        response += "\r\n"
        response += message
        writer.write(response.encode())
        await writer.drain()

    async def _send_json_response(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        data: dict[str, object],
    ) -> None:
        """Send a JSON response."""
        import json

        body = json.dumps(data).encode()
        status_text = {
            200: "OK",
            400: "Bad Request",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }.get(status, "Error")

        response = f"HTTP/1.1 {status} {status_text}\r\n"
        response += "Content-Type: application/json\r\n"
        response += f"Content-Length: {len(body)}\r\n"
        response += "\r\n"
        writer.write(response.encode())
        writer.write(body)
        await writer.drain()


async def run_tls_proxy(
    config: "Config",
    ca: "CertificateAuthority",
    scanner: ScannerPipeline,
    policy: PolicyEngine,
    identity: IdentityResolver,
    metrics: MetricsCollector,
) -> None:
    """Run the TLS intercepting proxy server."""
    proxy = TLSInterceptProxy(
        config=config,
        ca=ca,
        scanner=scanner,
        policy=policy,
        identity=identity,
        metrics=metrics,
    )

    server = await proxy.start(
        config.server.host,
        config.server.port,
    )

    try:
        async with server:
            await server.serve_forever()
    finally:
        await proxy.stop()
