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
from typing import TYPE_CHECKING, Any, Callable

import aiohttp
from aiohttp import web

if TYPE_CHECKING:
    from aiproxyguard.config import Config
    from aiproxyguard.control_plane import ControlPlaneClient

from aiproxyguard import __version__
from aiproxyguard.signatures.models import SignatureSet
from aiproxyguard.router import Router
from aiproxyguard.identity import IdentityResolver
from aiproxyguard.pipeline import PipelineRequest, RequestPipeline, UpstreamTarget
from aiproxyguard.policy import PolicyEngine
from aiproxyguard.scanner.pipeline import ScannerPipeline
from aiproxyguard.signatures.loader import load_signatures, get_signature_version
from aiproxyguard.metrics import MetricsCollector
from aiproxyguard.logging import get_logger, update_logging
from aiproxyguard.control_plane import init_client, get_client
from aiproxyguard.config import _to_bool
from aiproxyguard.cost_optimization import make_cache_control_mutator

logger = get_logger("server")


def register_cost_optimization_mutators(
    pipeline: RequestPipeline, config: "Config"
) -> None:
    """Register cost-optimization body mutators on a pipeline.

    Shared by both transports so the mutator set stays identical. The mutators
    are gated on live config flags (default off), so registering them
    unconditionally is safe -- they no-op until the feature is enabled.
    """
    pipeline.add_mutator(make_cache_control_mutator(config))


def register_control_plane_callbacks(
    cp_client: "ControlPlaneClient",
    *,
    scanner: ScannerPipeline,
    policy: PolicyEngine,
    config: "Config",
    metrics: MetricsCollector,
    on_signatures_reloaded: "Callable[[SignatureSet], None] | None" = None,
) -> None:
    """Wire control-plane config-update callbacks for a proxy instance.

    Shared by both transports (HTTP server and TLS intercept proxy) so a new
    callback type is registered in exactly one place. The HTTP path passes
    ``on_signatures_reloaded`` to also refresh its app-level signature cache.
    """
    # Policy updates
    cp_client.set_policy_update_callback(policy.update_config)

    # Signature hot-reload
    def on_signature_update(new_signatures: "SignatureSet") -> None:
        scanner.reload(new_signatures)
        metrics.set_signatures_loaded("free", len(new_signatures.signatures))
        if on_signatures_reloaded is not None:
            on_signatures_reloaded(new_signatures)

    cp_client.set_signature_update_callback(on_signature_update)

    # ML model hot-reload for tier-based model sync
    def on_ml_model_update(model_data: bytes, license_data: dict[str, Any]) -> None:
        if scanner.load_ml_from_bytes(model_data, model_config=license_data):
            model_id = license_data.get("model_id", "unknown")
            tier = license_data.get("tier", "unknown")
            logger.info(
                "ML model updated from control plane",
                extra={"model_id": model_id, "tier": tier},
            )

    cp_client.set_ml_model_callback(on_ml_model_update)

    # Reset highest-tier-wins tracking at the start of each model-sync pass so
    # the correct tier is chosen fresh from the entitled bundles (and a tier
    # downgrade takes effect) rather than the previous higher tier sticking.
    cp_client.set_model_sync_begin_callback(scanner.reset_active_ml_tier)

    # Logging config
    def on_logging_update(log_config: dict[str, Any]) -> None:
        update_logging(
            level=log_config.get("level"),
            format=log_config.get("format"),
            redact_keys=log_config.get("redact_keys"),
        )

    cp_client.set_logging_update_callback(on_logging_update)

    # Scanner config
    def on_scanner_update(scanner_config: dict[str, Any]) -> None:
        scanner.update_scanner_config(scanner_config)

    cp_client.set_scanner_update_callback(on_scanner_update)

    # ML classifier config
    def on_ml_config_update(ml_cfg: dict[str, Any]) -> None:
        scanner.update_ml_config(ml_cfg)

    cp_client.set_ml_config_update_callback(on_ml_config_update)

    # Security config
    def on_security_update(security_config: dict[str, Any]) -> None:
        if "failure_mode" in security_config:
            config.security.failure_mode = security_config["failure_mode"]
        if "scanner_timeout_ms" in security_config:
            config.security.scanner_timeout_ms = security_config["scanner_timeout_ms"]

    cp_client.set_security_update_callback(on_security_update)

    # Cost-optimization config (runtime toggle for the cache/routing features).
    # Registered through the section-handler registry so the cloud can enable or
    # disable it without a restart; the pipeline mutator reads the live flag.
    def on_cost_optimization_update(cost_config: dict[str, Any]) -> None:
        if "anthropic_prompt_cache" in cost_config:
            # Use _to_bool (same as boot parsing): a string "false"/"0" pushed
            # by the control plane must disable, not enable (bool("false")==True).
            config.cost_optimization.anthropic_prompt_cache = _to_bool(
                cost_config["anthropic_prompt_cache"], default=False
            )
            logger.info(
                "Cost-optimization config updated",
                extra={
                    "anthropic_prompt_cache": config.cost_optimization.anthropic_prompt_cache
                },
            )

    cp_client.register_section_handler("cost_optimization", on_cost_optimization_update)

    # Smart model routing (#305). Replaces the live routing config wholesale;
    # the pipeline's alias pre-step reads config.routing on every request. A
    # malformed section leaves the previous value in effect (the dispatcher
    # isolates a raising handler).
    def on_routing_update(routing_config: dict[str, Any]) -> None:
        if not isinstance(routing_config, dict):
            logger.warning("Ignoring invalid routing config", extra={"value": repr(routing_config)})
            return
        tasks = routing_config.get("tasks") or {}
        downgrades = routing_config.get("downgrades") or []
        dry_run = _to_bool(routing_config.get("dry_run", True), default=True)
        config.routing.tasks = tasks if isinstance(tasks, dict) else {}
        config.routing.downgrades = downgrades if isinstance(downgrades, list) else []
        config.routing.dry_run = dry_run
        logger.info(
            "Routing config updated",
            extra={"task_count": len(config.routing.tasks), "dry_run": dry_run},
        )

    cp_client.register_section_handler("routing", on_routing_update)

    # Policy-level scalar scan toggles. These are booleans, not nested objects,
    # so they must be processed even when false (the dispatcher skips only
    # absent keys, not falsy values). A malformed value (null, object, number,
    # unrecognized string) is rejected with a warning and leaves the current
    # state unchanged -- never silently coerced to a default that differs from
    # both the pushed value and the running config.
    def _strict_bool(value: object) -> "bool | None":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in (
            "true", "false", "1", "0", "yes", "no", "on", "off"
        ):
            return value.strip().lower() in ("true", "1", "yes", "on")
        return None

    def on_scan_request_update(value: object) -> None:
        enabled = _strict_bool(value)
        if enabled is None:
            logger.warning("Ignoring invalid scan_request value", extra={"value": repr(value)})
            return
        scanner.set_request_scanning(enabled)
        logger.info("Request scanning toggled", extra={"enabled": enabled})

    cp_client.register_section_handler("scan_request", on_scan_request_update)

    def on_scan_response_update(value: object) -> None:
        enabled = _strict_bool(value)
        if enabled is None:
            logger.warning("Ignoring invalid scan_response value", extra={"value": repr(value)})
            return
        scanner.set_response_scanning(enabled)
        logger.info("Response scanning toggled", extra={"enabled": enabled})

    cp_client.register_section_handler("scan_response", on_scan_response_update)

    # Set initial signature version from bundled signatures
    initial_sig_version = get_signature_version(config.signatures.path)
    if initial_sig_version:
        cp_client.set_initial_signature_version(initial_sig_version)


async def on_startup(app: web.Application) -> None:
    """Create shared HTTP session and start control plane client."""
    app["http_session"] = aiohttp.ClientSession()
    pipeline = RequestPipeline(
        config=app["config"],
        scanner=app["scanner"],
        policy=app["policy"],
        metrics=app["metrics"],
        session_getter=lambda: app["http_session"],
    )
    register_cost_optimization_mutators(pipeline, app["config"])
    app["pipeline"] = pipeline

    # Start control plane client
    cp_client = get_client()
    if cp_client:
        def cache_signatures(new_signatures: "SignatureSet") -> None:
            app["signatures"] = new_signatures

        register_control_plane_callbacks(
            cp_client,
            scanner=app["scanner"],
            policy=app["policy"],
            config=app["config"],
            metrics=app["metrics"],
            on_signatures_reloaded=cache_signatures,
        )
        await cp_client.start()


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


async def root_handler(request: web.Request) -> web.Response:
    """Root endpoint returning service info."""
    return web.json_response({
        "service": "AIProxyGuard",
        "version": __version__,
    })


async def check_handler(request: web.Request) -> web.Response:
    """Detection-only endpoint - runs scanner without forwarding to LLM."""
    app = request.app
    config: Config = app["config"]
    scanner: ScannerPipeline = app["scanner"]
    signatures: SignatureSet = app["signatures"]
    metrics: MetricsCollector = app["metrics"]

    # Parse request body
    try:
        body = await request.json()
    except Exception:
        return web.json_response(
            {"error": {"type": "invalid_json", "message": "Request body must be valid JSON"}},
            status=400,
        )

    # Validate body is a dict (not array, string, number, etc.)
    if not isinstance(body, dict):
        return web.json_response(
            {"error": {"type": "invalid_request", "message": "Request body must be a JSON object"}},
            status=400,
        )

    text = body.get("text")
    if not text or not isinstance(text, str):
        return web.json_response(
            {"error": {"type": "invalid_request", "message": "Request must include 'text' field"}},
            status=400,
        )

    # Run scanner with timeout
    scan_start = time.monotonic()
    try:
        timeout_s = config.security.scanner_timeout_ms / 1000.0
        scan_result = await asyncio.wait_for(
            scanner.scan_async(text),
            timeout=timeout_s,
        )
        scan_duration = time.monotonic() - scan_start
        metrics.record_scan("check", scan_result.action, scan_duration)

        # Look up signature name if we have a signature_id
        signature_name = None
        if scan_result.signature_id:
            sig = signatures.get(scan_result.signature_id)
            if sig:
                signature_name = sig.name

        # Don't expose signature_id or details to prevent reverse engineering
        return web.json_response({
            "action": scan_result.action,
            "category": scan_result.category,
            "signature_name": signature_name,
            "confidence": scan_result.confidence,
        })

    except asyncio.TimeoutError:
        scan_duration = time.monotonic() - scan_start
        metrics.record_scan("check", "timeout", scan_duration)
        logger.warning(
            "Check endpoint scanner timeout",
            extra={"timeout_ms": config.security.scanner_timeout_ms},
        )
        # Honor failure_mode: closed = fail safe (503), open = allow
        if config.security.failure_mode == "closed":
            return web.json_response(
                {"error": {"type": "scanner_timeout", "message": "Scanner timed out"}},
                status=503,
            )
        # Fail open - return allow
        return web.json_response({
            "action": "allow",
            "category": None,
            "signature_name": None,
            "confidence": 0.0,
        })
    except Exception as e:
        logger.error(f"Check endpoint error: {e}")
        # Honor failure_mode: closed = fail safe (503), open = allow
        if config.security.failure_mode == "closed":
            return web.json_response(
                {"error": {"type": "scanner_error", "message": "Scanner error"}},
                status=503,
            )
        # Fail open - return allow
        return web.json_response({
            "action": "allow",
            "category": None,
            "signature_name": None,
            "confidence": 0.0,
        })


async def proxy_handler(request: web.Request) -> web.Response:
    """Main proxy handler: resolve route and identity, then run the shared pipeline."""
    app = request.app
    config: Config = app["config"]
    router: Router = app["router"]
    identity: IdentityResolver = app["identity"]
    pipeline: RequestPipeline = app["pipeline"]

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

    result = await pipeline.process(PipelineRequest(
        method=request.method,
        path=path,
        headers={k.lower(): v for k, v in request.headers.items()},
        body=body,
        client_id=client_id,
        target=UpstreamTarget(
            provider=route.provider,
            url=route.upstream_url,
            auth_header=route.auth_header,
            timeout=route.timeout,
        ),
    ))

    return web.Response(
        status=result.status,
        body=result.body,
        headers=result.headers,
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
        init_client(config.control_plane, __version__, deployment_mode="http")

    # Lifecycle hooks
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # Routes
    app.router.add_get("/", root_handler)
    app.router.add_get("/healthz", health_handler)
    app.router.add_get("/readyz", readiness_handler)
    app.router.add_post("/check", check_handler)
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
        init_client(config.control_plane, __version__, deployment_mode="tls")
        cp_client = get_client()

        if cp_client:
            register_control_plane_callbacks(
                cp_client,
                scanner=scanner,
                policy=policy,
                config=config,
                metrics=metrics,
            )
            # Start the control plane client
            await cp_client.start()

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
