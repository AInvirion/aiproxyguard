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

"""HTTP server and proxy handler."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import aiohttp
from aiohttp import web

if TYPE_CHECKING:
    from aiproxyguard.config import Config
    from aiproxyguard.signatures.models import SignatureSet

from aiproxyguard.router import Router
from aiproxyguard.identity import IdentityResolver
from aiproxyguard.policy import PolicyEngine
from aiproxyguard.scanner.pipeline import ScannerPipeline
from aiproxyguard.signatures.loader import load_signatures
from aiproxyguard.metrics import MetricsCollector
from aiproxyguard.logging import get_logger, update_logging
from aiproxyguard.control_plane import init_client, get_client

logger = get_logger("server")


async def on_startup(app: web.Application) -> None:
    """Create shared HTTP session and start control plane client."""
    app["http_session"] = aiohttp.ClientSession()

    # Start control plane client
    cp_client = get_client()
    if cp_client:
        # Register policy update callback
        policy_engine: PolicyEngine = app["policy"]
        cp_client.set_policy_update_callback(policy_engine.update_config)

        # Register signature update callback for hot-reload
        scanner: ScannerPipeline = app["scanner"]
        metrics: MetricsCollector = app["metrics"]

        def on_signature_update(new_signatures: "SignatureSet") -> None:
            """Hot-reload signatures into the scanner without restart."""
            scanner.reload(new_signatures)
            app["signatures"] = new_signatures
            metrics.set_signatures_loaded("free", len(new_signatures.signatures))

        cp_client.set_signature_update_callback(on_signature_update)

        # Register ML model update callback for tier-based model sync
        def on_ml_model_update(model_data: bytes, license_data: dict) -> None:
            """Hot-reload ML model from control plane."""
            if scanner.load_ml_from_bytes(model_data):
                model_id = license_data.get("model_id", "unknown")
                tier = license_data.get("tier", "unknown")
                logger.info(
                    "ML model updated from control plane",
                    extra={"model_id": model_id, "tier": tier},
                )

        cp_client.set_ml_model_callback(on_ml_model_update)

        # Register logging config update callback
        def on_logging_update(config: dict) -> None:
            """Update logging settings from control plane."""
            update_logging(
                level=config.get("level"),
                format=config.get("format"),
                redact_keys=config.get("redact_keys"),
            )

        cp_client.set_logging_update_callback(on_logging_update)

        # Register scanner config update callback
        def on_scanner_update(config: dict) -> None:
            """Update scanner settings from control plane."""
            scanner.update_scanner_config(config)

        cp_client.set_scanner_update_callback(on_scanner_update)

        # Register ML classifier config update callback
        def on_ml_config_update(config: dict) -> None:
            """Update ML classifier settings from control plane."""
            scanner.update_ml_config(config)

        cp_client.set_ml_config_update_callback(on_ml_config_update)

        # Register security config update callback
        def on_security_update(config: dict) -> None:
            """Update security settings from control plane."""
            app_config: Config = app["config"]
            if "failure_mode" in config:
                app_config.security.failure_mode = config["failure_mode"]
            if "scanner_timeout_ms" in config:
                app_config.security.scanner_timeout_ms = config["scanner_timeout_ms"]

        cp_client.set_security_update_callback(on_security_update)

        await cp_client.start()

        # Sync ML model based on account tier (enterprise/professional models)
        await cp_client.sync_ml_model()


async def on_cleanup(app: web.Application) -> None:
    """Close shared HTTP session and stop control plane client."""
    # Stop control plane client
    cp_client = get_client()
    if cp_client:
        await cp_client.stop()

    await app["http_session"].close()


async def health_handler(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response({"status": "healthy"})


async def readiness_handler(request: web.Request) -> web.Response:
    """Readiness check endpoint."""
    app = request.app
    checks = {
        "config_loaded": app.get("config") is not None,
        "signatures_loaded": app.get("signatures") is not None,
    }

    if all(checks.values()):
        return web.json_response({"status": "ready", "checks": checks})
    else:
        return web.json_response({"status": "not_ready", "checks": checks}, status=503)


async def metrics_handler(request: web.Request) -> web.Response:
    """Prometheus metrics endpoint."""
    collector: MetricsCollector = request.app["metrics"]
    output, content_type_header = collector.generate_output()
    # aiohttp requires content_type and charset to be set separately;
    # parse them out of the full header value (e.g. "text/plain; charset=utf-8")
    parts = [p.strip() for p in content_type_header.split(";")]
    mime_type = parts[0]
    charset = None
    for part in parts[1:]:
        if part.lower().startswith("charset="):
            charset = part.split("=", 1)[1]
            break
    return web.Response(
        body=output,
        content_type=mime_type,
        charset=charset,
    )


async def proxy_handler(request: web.Request) -> web.Response:
    """Main proxy handler."""
    app = request.app
    config: Config = app["config"]
    router: Router = app["router"]
    scanner: ScannerPipeline = app["scanner"]
    policy: PolicyEngine = app["policy"]
    identity: IdentityResolver = app["identity"]
    metrics: MetricsCollector = app["metrics"]

    start_time = time.monotonic()
    path = request.path_qs

    # Route request
    route = router.match(path)
    if not route:
        return web.json_response(
            {"error": {"type": "not_found", "message": f"Unknown provider: {path}"}},
            status=404,
        )

    # Resolve client identity
    client_id = identity.resolve(dict(request.headers), request.remote)

    # Check request size limit before reading body
    content_length = request.content_length
    if content_length is not None and content_length > config.security.max_request_size:
        return web.json_response(
            {"error": {"type": "payload_too_large", "message": "Request body exceeds size limit"}},
            status=413,
        )

    # Read request body with size limit
    body = await request.read()
    if len(body) > config.security.max_request_size:
        return web.json_response(
            {"error": {"type": "payload_too_large", "message": "Request body exceeds size limit"}},
            status=413,
        )

    # Scan request (if enabled and has body)
    if config.scanner.enabled and body:
        scan_start = time.monotonic()
        try:
            text = body.decode("utf-8")
            # Run CPU-bound scanning in thread pool with timeout
            timeout_s = config.security.scanner_timeout_ms / 1000.0
            scan_result = await asyncio.wait_for(
                scanner.scan_async(text),
                timeout=timeout_s,
            )
            scan_duration = time.monotonic() - scan_start
            metrics.record_scan("pipeline", scan_result.action, scan_duration)

            # Apply policy
            final_action = policy.resolve(client_id, scan_result)

            if final_action == "block":
                metrics.record_detection(
                    scan_result.category or "unknown",
                    "block",
                    scan_result.signature_id,
                )
                # Log details server-side only (never expose to clients)
                logger.warning(
                    "Request blocked",
                    extra={
                        "category": scan_result.category,
                        "signature_id": scan_result.signature_id,
                        "client_id": client_id,
                        "internal_details": scan_result.details,  # For debugging only
                    },
                )
                # Report to control plane
                cp_client = get_client()
                if cp_client:
                    asyncio.create_task(cp_client.report_detection(
                        event_type="block",
                        category=scan_result.category or "unknown",
                        signature_id=scan_result.signature_id,
                        latency_ms=int(scan_duration * 1000),
                        provider=route.provider,
                        endpoint=path,
                    ))
                # Return generic message - never expose signature patterns
                return web.json_response({
                    "error": {
                        "type": "content_blocked",
                        "code": f"{scan_result.category}_detected",
                        "message": "Request blocked: policy violation detected",
                        "category": scan_result.category,
                    }
                }, status=400)

            if final_action in ("warn", "log"):
                metrics.record_detection(
                    scan_result.category or "unknown",
                    final_action,
                    scan_result.signature_id,
                )
                # Report to control plane
                cp_client = get_client()
                if cp_client:
                    asyncio.create_task(cp_client.report_detection(
                        event_type=final_action,
                        category=scan_result.category or "unknown",
                        signature_id=scan_result.signature_id,
                        latency_ms=int(scan_duration * 1000),
                        provider=route.provider,
                        endpoint=path,
                    ))
                logger.warning(
                    "Detection",
                    extra={
                        "action": final_action,
                        "category": scan_result.category,
                        "client_id": client_id,
                        "signature_id": scan_result.signature_id,
                    },
                )
        except asyncio.TimeoutError:
            # Scanner timed out - use failure mode
            scan_duration = time.monotonic() - scan_start
            metrics.record_scan("pipeline", "timeout", scan_duration)
            logger.warning(
                "Scanner timeout",
                extra={"timeout_ms": config.security.scanner_timeout_ms},
            )
            if config.security.failure_mode == "closed":
                return web.json_response(
                    {"error": {"type": "scanner_timeout", "message": "Scanner timed out"}},
                    status=503,
                )
        except Exception as e:
            # Scanner error - use failure mode
            if config.security.failure_mode == "closed":
                return web.json_response(
                    {"error": {"type": "scanner_error", "message": "Scanner unavailable"}},
                    status=503,
                )
            logger.error(f"Scanner error: {e}")

    # Forward to upstream
    try:
        session: aiohttp.ClientSession = app["http_session"]
        # Build headers (copy relevant headers)
        headers = {}
        # Forward standard and vendor-specific headers required by LLM providers
        allowed_headers = (
            # Standard headers
            "content-type", "accept", "accept-encoding", "accept-language",
            # OpenAI headers
            "openai-organization", "openai-project", "openai-beta",
            # Anthropic headers
            "anthropic-version", "anthropic-beta", "anthropic-dangerous-direct-browser-access",
            # OpenRouter headers
            "x-title", "http-referer",
            # Common request IDs
            "x-request-id", "x-correlation-id",
        )
        for key in allowed_headers:
            if key in request.headers:
                headers[key] = request.headers[key]

        # Forward auth header based on route config, with fallbacks
        auth_headers_to_check = ["authorization", "api-key", "x-api-key"]
        if route.auth_header:
            # Prioritize the configured auth header
            auth_headers_to_check = [route.auth_header.lower()] + [
                h for h in auth_headers_to_check if h != route.auth_header.lower()
            ]
        for key in auth_headers_to_check:
            if key in request.headers:
                headers[key] = request.headers[key]
                break  # Only forward one auth header

        async with session.request(
            method=request.method,
            url=route.upstream_url,
            headers=headers,
            data=body,
            timeout=aiohttp.ClientTimeout(total=route.timeout),
        ) as resp:
            # Check response size limit before reading
            upstream_content_length = resp.content_length
            if upstream_content_length is not None and upstream_content_length > config.security.max_response_size:
                logger.warning(
                    "Response too large",
                    extra={"content_length": upstream_content_length, "limit": config.security.max_response_size},
                )
                return web.json_response(
                    {"error": {"type": "response_too_large", "message": "Upstream response exceeds size limit"}},
                    status=502,
                )

            response_body = await resp.read()

            # Also check actual size in case Content-Length was missing/wrong
            if len(response_body) > config.security.max_response_size:
                logger.warning(
                    "Response too large (after read)",
                    extra={"size": len(response_body), "limit": config.security.max_response_size},
                )
                return web.json_response(
                    {"error": {"type": "response_too_large", "message": "Upstream response exceeds size limit"}},
                    status=502,
                )

            duration = time.monotonic() - start_time
            metrics.record_request(route.provider, request.method, resp.status, duration)

            # Build response headers, forwarding relevant upstream headers
            response_headers = {}
            for header in (
                "content-type",
                "x-request-id",
                "retry-after",
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
                "x-ratelimit-reset",
            ):
                if header in resp.headers:
                    response_headers[header] = resp.headers[header]

            # Response scanning (if enabled)
            response_scanner = scanner.response_scanner
            if response_scanner and response_scanner.enabled and response_body:
                scan_start = time.monotonic()
                try:
                    response_text = response_body.decode("utf-8")
                    # Run CPU-bound scanning in thread pool with timeout
                    timeout_s = config.security.scanner_timeout_ms / 1000.0
                    response_scan_result = await asyncio.wait_for(
                        asyncio.to_thread(response_scanner.scan, response_text),
                        timeout=timeout_s,
                    )
                    scan_duration = time.monotonic() - scan_start
                    metrics.record_scan("response", "block" if response_scan_result.blocked else "allow", scan_duration)

                    if response_scan_result.has_detections:
                        # Report detection to control plane
                        cp_client = get_client()
                        if cp_client:
                            asyncio.create_task(cp_client.report_detection(
                                event_type="response_detection",
                                category=response_scan_result.category or "unknown",
                                signature_id=response_scan_result.signature_id,
                                latency_ms=int(scan_duration * 1000),
                                provider=route.provider,
                                endpoint=path,
                            ))

                        if response_scan_result.blocked:
                            metrics.record_detection(
                                response_scan_result.category or "unknown",
                                "block",
                                response_scan_result.signature_id,
                            )
                            logger.warning(
                                "Response blocked",
                                extra={
                                    "category": response_scan_result.category,
                                    "signature_id": response_scan_result.signature_id,
                                    "client_id": client_id,
                                    "internal_details": response_scan_result.details,
                                },
                            )
                            # Return generic message - never expose signature patterns
                            return web.json_response({
                                "error": {
                                    "type": "response_blocked",
                                    "code": f"{response_scan_result.category}_detected",
                                    "message": "Response blocked: sensitive content detected",
                                    "category": response_scan_result.category,
                                }
                            }, status=502)
                        else:
                            # Log non-blocking detections
                            metrics.record_detection(
                                response_scan_result.category or "unknown",
                                "warn",
                                response_scan_result.signature_id,
                            )
                            logger.warning(
                                "Response detection (non-blocking)",
                                extra={
                                    "category": response_scan_result.category,
                                    "signature_id": response_scan_result.signature_id,
                                    "client_id": client_id,
                                },
                            )
                except asyncio.TimeoutError:
                    scan_duration = time.monotonic() - scan_start
                    metrics.record_scan("response", "timeout", scan_duration)
                    logger.warning(
                        "Response scanner timeout",
                        extra={"timeout_ms": config.security.scanner_timeout_ms},
                    )
                    # Fail open for response scanning - return the response
                except Exception as e:
                    logger.error(f"Response scanner error: {e}")
                    # In case of scanner error, we still return the response
                    # (fail open for response scanning by default)

            return web.Response(
                status=resp.status,
                body=response_body,
                headers=response_headers,
            )
    except aiohttp.ClientError as e:
        duration = time.monotonic() - start_time
        metrics.record_request(route.provider, request.method, 502, duration)
        logger.error(f"Upstream error: {e}")
        return web.json_response(
            {"error": {"type": "upstream_error", "message": str(e)}},
            status=502,
        )


def create_app(config: Config) -> web.Application:
    """Create the aiohttp application."""
    # Set client_max_size to honor configured max_request_size
    app = web.Application(client_max_size=config.security.max_request_size)

    # Store config
    app["config"] = config

    # Initialize components - handle missing signatures path gracefully
    try:
        signatures = load_signatures(config.signatures.path)
    except FileNotFoundError:
        from aiproxyguard.signatures.models import SignatureSet
        signatures = SignatureSet(signatures=[])

    app["signatures"] = signatures
    app["router"] = Router(config.upstreams)
    app["scanner"] = ScannerPipeline(config.scanner, signatures, config.ml_classifier)
    app["policy"] = PolicyEngine(
        default_action=config.policy.default_action,
        categories={
            cat: {"action": cfg.action, "threshold": cfg.threshold}
            for cat, cfg in config.policy.categories.items()
        },
        allowlists=config.policy.allowlists,
    )
    app["identity"] = IdentityResolver(
        method=config.identity.method,
        header_name=config.identity.header_name,
        fallback_header=config.identity.fallback_header,
        trust_xff=config.identity.trust_xff,
        hash_token=config.identity.hash_token,
    )
    app["metrics"] = MetricsCollector()

    # Set signature count metric
    app["metrics"].set_signatures_loaded("free", len(signatures.signatures))

    # Initialize control plane client
    if config.control_plane.enabled:
        from aiproxyguard import __version__
        init_client(config.control_plane, __version__)

    # Lifecycle hooks
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # Routes
    app.router.add_get("/healthz", health_handler)
    app.router.add_get("/readyz", readiness_handler)
    # Only expose /metrics if enabled in config
    if config.metrics.enabled:
        app.router.add_get("/metrics", metrics_handler)
    app.router.add_route("*", "/{path:.*}", proxy_handler)

    return app


async def run_server(config: Config) -> None:
    """Run the server."""
    # Check if TLS interception is enabled
    if config.tls.enabled:
        await _run_tls_server(config)
    else:
        await _run_http_server(config)


async def _run_http_server(config: Config) -> None:
    """Run the standard HTTP proxy server."""
    app = create_app(config)
    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, config.server.host, config.server.port)
    await site.start()

    logger.info(
        "Server started",
        extra={"host": config.server.host, "port": config.server.port},
    )

    # Keep running until cancelled
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await runner.cleanup()


async def _run_tls_server(config: Config) -> None:
    """Run the TLS-intercepting proxy server."""
    from aiproxyguard.tls import CertificateAuthority
    from aiproxyguard.tls_proxy import run_tls_proxy
    from aiproxyguard.signatures.models import SignatureSet

    # Load CA for certificate generation
    ca = CertificateAuthority(
        ca_cert_path=config.tls.ca_cert,
        ca_key_path=config.tls.ca_key,
        cache_size=config.tls.cert_cache_size,
        cert_validity_days=config.tls.cert_validity_days,
    )
    ca.load()

    # Initialize components
    try:
        signatures = load_signatures(config.signatures.path)
    except FileNotFoundError:
        signatures = SignatureSet(signatures=[])

    scanner = ScannerPipeline(config.scanner, signatures, config.ml_classifier)
    policy = PolicyEngine(
        default_action=config.policy.default_action,
        categories={
            cat: {"action": cfg.action, "threshold": cfg.threshold}
            for cat, cfg in config.policy.categories.items()
        },
        allowlists=config.policy.allowlists,
    )
    identity = IdentityResolver(
        method=config.identity.method,
        header_name=config.identity.header_name,
        fallback_header=config.identity.fallback_header,
        trust_xff=config.identity.trust_xff,
        hash_token=config.identity.hash_token,
    )
    metrics = MetricsCollector()
    metrics.set_signatures_loaded("free", len(signatures.signatures))

    # Initialize control plane client (same as HTTP path)
    cp_client = None
    if config.control_plane.enabled:
        from aiproxyguard import __version__
        init_client(config.control_plane, __version__)
        cp_client = get_client()

        if cp_client:
            # Register policy update callback
            cp_client.set_policy_update_callback(policy.update_config)

            # Register signature update callback for hot-reload
            def on_signature_update(new_signatures: "SignatureSet") -> None:
                """Hot-reload signatures into the scanner without restart."""
                scanner.reload(new_signatures)
                metrics.set_signatures_loaded("free", len(new_signatures.signatures))

            cp_client.set_signature_update_callback(on_signature_update)

            # Register ML model update callback for tier-based model sync
            def on_ml_model_update(model_data: bytes, license_data: dict) -> None:
                """Hot-reload ML model from control plane."""
                if scanner.load_ml_from_bytes(model_data):
                    model_id = license_data.get("model_id", "unknown")
                    tier = license_data.get("tier", "unknown")
                    logger.info(
                        "ML model updated from control plane",
                        extra={"model_id": model_id, "tier": tier},
                    )

            cp_client.set_ml_model_callback(on_ml_model_update)

            # Register logging config update callback
            def on_logging_update(log_config: dict) -> None:
                """Update logging settings from control plane."""
                update_logging(
                    level=log_config.get("level"),
                    format=log_config.get("format"),
                    redact_keys=log_config.get("redact_keys"),
                )

            cp_client.set_logging_update_callback(on_logging_update)

            # Register scanner config update callback
            def on_scanner_update(scanner_config: dict) -> None:
                """Update scanner settings from control plane."""
                scanner.update_scanner_config(scanner_config)

            cp_client.set_scanner_update_callback(on_scanner_update)

            # Register ML classifier config update callback
            def on_ml_config_update(ml_cfg: dict) -> None:
                """Update ML classifier settings from control plane."""
                scanner.update_ml_config(ml_cfg)

            cp_client.set_ml_config_update_callback(on_ml_config_update)

            # Register security config update callback
            def on_security_update(security_config: dict) -> None:
                """Update security settings from control plane."""
                if "failure_mode" in security_config:
                    config.security.failure_mode = security_config["failure_mode"]
                if "scanner_timeout_ms" in security_config:
                    config.security.scanner_timeout_ms = security_config["scanner_timeout_ms"]

            cp_client.set_security_update_callback(on_security_update)

            # Start the control plane client
            await cp_client.start()

            # Sync ML model based on account tier (enterprise/professional models)
            await cp_client.sync_ml_model()

    logger.info(
        "Starting TLS intercept proxy",
        extra={
            "host": config.server.host,
            "port": config.server.port,
            "ca_cert": config.tls.ca_cert,
            "control_plane_enabled": config.control_plane.enabled,
        },
    )

    try:
        await run_tls_proxy(
            config=config,
            ca=ca,
            scanner=scanner,
            policy=policy,
            identity=identity,
            metrics=metrics,
        )
    finally:
        # Stop control plane client on shutdown
        if cp_client:
            await cp_client.stop()
