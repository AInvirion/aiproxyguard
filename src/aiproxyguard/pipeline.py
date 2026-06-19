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

"""Transport-agnostic request processing pipeline.

Canonical flow shared by the HTTP server and the TLS intercept proxy:

    read -> parse -> mutate -> serialize -> scan -> forward -> scan response

The scanner always inspects the exact bytes that are forwarded upstream.
Body mutators run before scanning; if no mutator changes the body (the
default — none are registered today), the original raw bytes pass through
untouched. If the body cannot be parsed as JSON, mutation is skipped and
the raw bytes are forwarded (fail-open).
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

import aiohttp

if TYPE_CHECKING:
    from aiproxyguard.config import Config

from aiproxyguard.cache import CachedResponse, ResponseCache
from aiproxyguard.control_plane import get_client
from aiproxyguard.logging import get_logger
from aiproxyguard.metrics import MetricsCollector
from aiproxyguard.policy import PolicyEngine
from aiproxyguard.complexity import extract_prompt_text, score_text
from aiproxyguard.routing import (
    ROUTED_MODEL_HEADER,
    ROUTING_DECISION_HEADER,
    capability_ok,
    parse_router_task,
    rewrite_model,
    sanitize_header_value,
    select_downgrade,
    select_route,
)
from aiproxyguard.scanner.pipeline import ScannerPipeline
from aiproxyguard.tokens import billed_tokens, count_tokens

logger = get_logger("pipeline")

# Standard and vendor-specific headers forwarded to upstream LLM providers
FORWARDED_HEADERS = (
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

# Auth headers checked in order when the upstream config does not name one
AUTH_HEADER_FALLBACKS = ("authorization", "api-key", "x-api-key")

# Upstream response headers forwarded back to the client
RESPONSE_HEADERS = (
    "content-type",
    "x-request-id",
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
)

# Marks a response served from (or stored to) the exact-match response cache.
CACHE_STATUS_HEADER = "x-aiproxyguard-cache"


@dataclass
class UpstreamTarget:
    """Resolved upstream destination for a request."""

    provider: str
    url: str
    auth_header: str | None = None
    timeout: float = 60.0


@dataclass
class PipelineRequest:
    """A client request normalized for pipeline processing.

    Header keys must be lowercase.
    """

    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    client_id: str
    target: UpstreamTarget
    # Headers to add to the response, written during request processing (e.g.
    # the smart-routing decision). Merged into the response headers in _forward.
    response_annotations: dict[str, str] = field(default_factory=dict)
    # Ordered fallback models to try on an upstream 5xx (set by routing).
    routing_retry: list[str] = field(default_factory=list)
    # Smart-routing provenance for usage telemetry (set by the routing steps):
    #   requested_model     -- the original model field, pre-rewrite
    #   routed_target_model -- the chosen/would-be cheaper model
    #   routing_mode        -- "applied" (rewritten) or "dry_run" (decided only)
    # The control plane derives realized vs projected savings from these.
    requested_model: str | None = None
    routed_target_model: str | None = None
    routing_mode: str | None = None


@dataclass
class PipelineResult:
    """Response to render back to the client."""

    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    reason: str | None = None


# A mutator receives the parsed JSON body and the upstream target, and
# returns the modified body dict, or None to indicate no change.
BodyMutator = Callable[[dict[str, Any], UpstreamTarget], "dict[str, Any] | None"]


def _json_result(status: int, payload: dict[str, Any]) -> PipelineResult:
    return PipelineResult(
        status=status,
        body=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
    )


def _extract_model_and_tokens(text: str) -> tuple[str | None, int | None]:
    """Best-effort model name and token count extraction for telemetry."""
    model = None
    input_tokens = None
    try:
        body_json = json.loads(text)
        if isinstance(body_json, dict):
            model = body_json.get("model")
            if model is not None:
                model = str(model)[:100]  # Truncate to 100 chars
        input_tokens = count_tokens(text, model)
    except Exception:
        pass  # Best effort - don't fail the block
    return model, input_tokens


class RequestPipeline:
    """Shared scan/mutate/forward pipeline used by both proxy transports."""

    def __init__(
        self,
        config: "Config",
        scanner: ScannerPipeline,
        policy: PolicyEngine,
        metrics: MetricsCollector,
        session_getter: Callable[[], aiohttp.ClientSession],
        cache: ResponseCache | None = None,
    ) -> None:
        self._config = config
        self._scanner = scanner
        self._policy = policy
        self._metrics = metrics
        self._session_getter = session_getter
        self._cache = cache
        self._mutators: list[BodyMutator] = []

    def add_mutator(self, mutator: BodyMutator) -> None:
        """Register a body mutator (e.g. prompt cache injection, model routing)."""
        self._mutators.append(mutator)

    async def process(self, request: PipelineRequest) -> PipelineResult:
        """Run a request through route -> mutate -> scan -> forward -> scan response."""
        # Resolve an explicit router:<task> alias before anything else: it may
        # rewrite request.body (the model field), set the routing retry plan,
        # and annotate the response -- or fail closed with a 400.
        routing_error = self._resolve_routing_alias(request)
        if routing_error is not None:
            return routing_error

        # Transparent complexity-scored downgrade for requests that did NOT opt
        # in (no router: alias). No-op unless downgrades are configured; ships
        # behind dry_run (default) so it only annotates, never rewrites.
        self._maybe_downgrade(request)

        outbound = self._apply_mutations(request)

        blocked = await self._scan_request(request, outbound)
        if blocked is not None:
            return blocked

        return await self._forward(request, outbound)

    def _resolve_routing_alias(self, request: PipelineRequest) -> PipelineResult | None:
        """Resolve a ``model: "router:<task>"`` alias to a concrete model.

        Mutates ``request.body`` (model field), sets ``request.routing_retry``
        (the ordered 5xx fallback plan), and annotates the response with the
        chosen model. Fail-closed: an unknown task or an empty pool returns a
        400 rather than forwarding a bogus ``router:*`` model upstream. A
        non-router request (or unparseable body) is a no-op (returns None).
        """
        routing = self._config.routing
        if not routing.tasks or not request.body:
            return None
        try:
            body_json = json.loads(request.body)
        except Exception:
            return None
        if not isinstance(body_json, dict):
            return None

        requested = body_json.get("model")
        task_name = parse_router_task(requested)
        if task_name is None:
            return None

        task_cfg = routing.tasks.get(task_name)
        if not isinstance(task_cfg, dict):
            self._metrics.record_routing("alias", "unknown_task")
            logger.warning(
                "Unknown router task; rejecting",
                extra={"task": task_name, "client_id": request.client_id},
            )
            return _json_result(400, {
                "error": {
                    "type": "unknown_router_task",
                    "message": f"Unknown router task: {task_name}",
                }
            })

        decision = select_route(task_cfg, capability_ok(body_json))
        if decision is None:
            self._metrics.record_routing("alias", "no_route")
            return _json_result(400, {
                "error": {
                    "type": "no_route",
                    "message": f"No model configured for router task: {task_name}",
                }
            })

        body_json["model"] = decision.chosen
        request.body = json.dumps(body_json).encode()
        request.routing_retry = decision.retry_plan
        request.response_annotations[ROUTED_MODEL_HEADER] = sanitize_header_value(
            decision.chosen
        )
        # Provenance for usage telemetry. The requested side is the alias token
        # (not a real model name), so the control plane won't price it -- alias
        # routes show up in the requested->routed breakdown without fabricated $.
        request.requested_model = str(requested)[:100] if requested is not None else None
        request.routed_target_model = decision.chosen
        request.routing_mode = "applied"
        self._metrics.record_routing("alias", "routed")
        logger.info(
            "Routed request via task alias",
            extra={
                "task": task_name,
                "model": decision.chosen,
                "client_id": request.client_id,
            },
        )
        return None

    def _maybe_downgrade(self, request: PipelineRequest) -> None:
        """Transparent complexity-scored same-provider downgrade (#305 1b).

        Only for requests that did NOT opt into a router alias. Scores the
        prompt; if it is simple enough and a downgrade pair matches the
        request's provider + current model (and the request is capability-safe),
        either annotate the dry-run decision (default) or rewrite the model.
        Never rewrites in dry-run mode.
        """
        routing = self._config.routing
        downgrades = routing.downgrades
        if not downgrades or not request.body:
            return
        # Skip if an alias already routed this request.
        if ROUTED_MODEL_HEADER in request.response_annotations:
            return
        try:
            body_json = json.loads(request.body)
        except Exception:
            return
        if not isinstance(body_json, dict):
            return
        model = body_json.get("model")
        if not isinstance(model, str) or parse_router_task(model) is not None:
            return  # missing model, or a router: alias (handled elsewhere)

        if not capability_ok(body_json):
            self._metrics.record_routing("downgrade", "skipped_excluded")
            return

        # Fail closed: if we can't extract any prompt text (unknown body shape),
        # don't treat the empty string as "simple" and downgrade it.
        prompt_text = extract_prompt_text(body_json)
        if not prompt_text.strip():
            self._metrics.record_routing("downgrade", "skipped")
            return

        score = score_text(prompt_text, model)
        target = select_downgrade(
            model, request.target.provider, downgrades, score.downgrade_eligible
        )
        if target is None:
            self._metrics.record_routing("downgrade", "skipped")
            return

        # Record provenance for usage telemetry in both branches. The control
        # plane prices (price(requested) - price(target)) x billed tokens:
        # realized when applied, projected (would-be) when dry-run.
        request.requested_model = model
        request.routed_target_model = target

        if routing.dry_run:
            request.response_annotations[ROUTING_DECISION_HEADER] = sanitize_header_value(
                f"would-route {model}->{target} tier={score.tier} score={score.score}"
            )
            request.routing_mode = "dry_run"
            self._metrics.record_routing("downgrade", "dry_run")
            logger.info(
                "Downgrade candidate (dry-run; not applied)",
                extra={
                    "from": model, "to": target, "tier": score.tier,
                    "score": score.score, "client_id": request.client_id,
                },
            )
            return

        body_json["model"] = target
        request.body = json.dumps(body_json).encode()
        request.response_annotations[ROUTED_MODEL_HEADER] = sanitize_header_value(target)
        request.routing_mode = "applied"
        self._metrics.record_routing("downgrade", "routed")
        logger.info(
            "Downgraded request to cheaper model",
            extra={
                "from": model, "to": target, "tier": score.tier,
                "client_id": request.client_id,
            },
        )

    def _apply_mutations(self, request: PipelineRequest) -> bytes:
        """Apply registered body mutators and return the outbound bytes.

        With no mutators (or no body), the original bytes pass through
        untouched. Parse failures fail open: raw bytes are forwarded.
        """
        if not self._mutators or not request.body:
            return request.body

        try:
            body_json = json.loads(request.body)
        except Exception:
            logger.debug(
                "Body mutation skipped: request body is not valid JSON",
                extra={"provider": request.target.provider},
            )
            return request.body

        if not isinstance(body_json, dict):
            return request.body

        mutated = False
        for mutator in self._mutators:
            try:
                result = mutator(body_json, request.target)
            except Exception as e:
                logger.error(f"Body mutator error (skipped): {e}")
                continue
            if result is not None:
                body_json = result
                mutated = True

        if not mutated:
            return request.body

        outbound = json.dumps(body_json).encode()
        logger.info(
            "Request body mutated; scanner will inspect mutated payload",
            extra={"provider": request.target.provider, "client_id": request.client_id},
        )
        return outbound

    async def _scan_request(
        self, request: PipelineRequest, outbound: bytes
    ) -> PipelineResult | None:
        """Scan the outbound bytes. Returns a result if the request must not be forwarded."""
        config = self._config
        if not (config.scanner.enabled and config.scanner.request_scanning and outbound):
            return None

        scan_start = time.monotonic()
        try:
            text = outbound.decode("utf-8")
            # Run CPU-bound scanning in thread pool with timeout
            timeout_s = config.security.scanner_timeout_ms / 1000.0
            scan_result = await asyncio.wait_for(
                self._scanner.scan_async(text),
                timeout=timeout_s,
            )
            scan_duration = time.monotonic() - scan_start
            self._metrics.record_scan("pipeline", scan_result.action, scan_duration)

            # Apply policy
            final_action = self._policy.resolve(request.client_id, scan_result)

            if final_action == "block":
                self._metrics.record_detection(
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
                        "client_id": request.client_id,
                        "internal_details": scan_result.details,  # For debugging only
                    },
                )
                model, input_tokens = _extract_model_and_tokens(text)
                self._report_detection(
                    event_type="block",
                    category=scan_result.category or "unknown",
                    signature_id=scan_result.signature_id,
                    latency_ms=int(scan_duration * 1000),
                    provider=request.target.provider,
                    endpoint=request.path,
                    model=model,
                    input_tokens=input_tokens,
                )
                # Return generic message - never expose signature patterns
                return _json_result(400, {
                    "error": {
                        "type": "content_blocked",
                        "code": f"{scan_result.category}_detected",
                        "message": "Request blocked: policy violation detected",
                        "category": scan_result.category,
                    }
                })

            if final_action in ("warn", "log"):
                self._metrics.record_detection(
                    scan_result.category or "unknown",
                    final_action,
                    scan_result.signature_id,
                )
                self._report_detection(
                    event_type=final_action,
                    category=scan_result.category or "unknown",
                    signature_id=scan_result.signature_id,
                    latency_ms=int(scan_duration * 1000),
                    provider=request.target.provider,
                    endpoint=request.path,
                )
                logger.warning(
                    "Detection",
                    extra={
                        "action": final_action,
                        "category": scan_result.category,
                        "client_id": request.client_id,
                        "signature_id": scan_result.signature_id,
                    },
                )
        except asyncio.TimeoutError:
            # Scanner timed out - use failure mode
            scan_duration = time.monotonic() - scan_start
            self._metrics.record_scan("pipeline", "timeout", scan_duration)
            logger.warning(
                "Scanner timeout",
                extra={"timeout_ms": config.security.scanner_timeout_ms},
            )
            if config.security.failure_mode == "closed":
                return _json_result(503, {
                    "error": {"type": "scanner_timeout", "message": "Scanner timed out"}
                })
        except Exception as e:
            # Scanner error - use failure mode
            if config.security.failure_mode == "closed":
                return _json_result(503, {
                    "error": {"type": "scanner_error", "message": "Scanner unavailable"}
                })
            logger.error(f"Scanner error: {e}")

        return None

    async def _forward(
        self, request: PipelineRequest, outbound: bytes
    ) -> PipelineResult:
        """Forward the outbound bytes upstream and scan the response.

        When routing populated ``request.routing_retry``, an upstream 5xx (or a
        connection error) retries the next model in the plan (remaining pool,
        then fallback). Usage reporting and response scanning run only on the
        final served response; intermediate 5xx bodies are never scanned. The
        retry count is bounded by the plan length, and a 4xx is never retried.
        """
        config = self._config
        target = request.target
        retry_models = list(request.routing_retry)
        attempt_body = outbound

        # Exact-match response cache (#307). Keyed on the EFFECTIVE (post-routing)
        # request. A hit skips the upstream call entirely but STILL runs response
        # scanning (never a policy bypass) before serving.
        cache_key = None
        if self._cache is not None and self._cache.enabled and self._cache_policy_ok():
            cache_key = self._cache.compute_key(target.provider, request.path, attempt_body)
            if cache_key is not None:
                cached = await self._cache.get(cache_key)
                if cached is not None:
                    blocked = await self._scan_response(request, cached.body)
                    if blocked is not None:
                        return blocked
                    headers = {
                        "content-type": cached.content_type,
                        CACHE_STATUS_HEADER: "hit",
                    }
                    headers.update(request.response_annotations)
                    logger.info(
                        "Response cache hit",
                        extra={"provider": target.provider, "client_id": request.client_id},
                    )
                    return PipelineResult(status=cached.status, body=cached.body, headers=headers)

        while True:
            attempt_start = time.monotonic()
            try:
                session = self._session_getter()
                headers = self._build_forward_headers(request)

                async with session.request(
                    method=request.method,
                    url=target.url,
                    headers=headers,
                    data=attempt_body if attempt_body else None,
                    timeout=aiohttp.ClientTimeout(total=target.timeout),
                ) as resp:
                    # Check response size limit before reading
                    upstream_content_length = resp.content_length
                    if upstream_content_length is not None and upstream_content_length > config.security.max_response_size:
                        logger.warning(
                            "Response too large",
                            extra={
                                "content_length": upstream_content_length,
                                "limit": config.security.max_response_size,
                            },
                        )
                        return _json_result(502, {
                            "error": {"type": "response_too_large", "message": "Upstream response exceeds size limit"}
                        })

                    response_body = await resp.read()

                    # Also check actual size in case Content-Length was missing/wrong
                    if len(response_body) > config.security.max_response_size:
                        logger.warning(
                            "Response too large (after read)",
                            extra={
                                "size": len(response_body),
                                "limit": config.security.max_response_size,
                            },
                        )
                        return _json_result(502, {
                            "error": {"type": "response_too_large", "message": "Upstream response exceeds size limit"}
                        })

                    # Retry on upstream 5xx if the routing plan has another model.
                    next_body = self._next_routing_attempt(
                        request, attempt_body, retry_models
                    ) if 500 <= resp.status < 600 else None
                    if next_body is not None:
                        self._metrics.record_request(
                            target.provider, request.method, resp.status,
                            time.monotonic() - attempt_start,
                        )
                        logger.warning(
                            "Upstream 5xx; retrying next routed model",
                            extra={"status": resp.status, "provider": target.provider},
                        )
                        # Preserve the invariant that the scanner inspects the
                        # exact bytes forwarded: rescan the rewritten body.
                        blocked = await self._scan_request(request, next_body)
                        if blocked is not None:
                            return blocked
                        attempt_body = next_body
                        continue

                    duration = time.monotonic() - attempt_start
                    self._metrics.record_request(target.provider, request.method, resp.status, duration)

                    # Report billed usage before response scanning: the provider
                    # billed for this completion even if we block the response.
                    self._report_usage(request, response_body, resp.status, duration)

                    blocked = await self._scan_response(request, response_body)
                    if blocked is not None:
                        return blocked

                    # Store a cacheable, successful response for future exact hits
                    # (off the response path so Redis latency never blocks the client).
                    # Recompute the key from the FINAL served body so a 5xx fallback
                    # to a different model is stored under that model's key, never
                    # the originally-requested one.
                    if cache_key is not None and 200 <= resp.status < 300:
                        store_key = self._cache.compute_key(
                            target.provider, request.path, attempt_body
                        )
                        if store_key is not None:
                            self._schedule_cache_store(
                                store_key,
                                response_body,
                                resp.headers.get("content-type", "application/json"),
                                resp.status,
                            )

                    response_headers = {
                        header: resp.headers[header]
                        for header in RESPONSE_HEADERS
                        if header in resp.headers
                    }
                    # Surface request-processing annotations (e.g. routed model).
                    response_headers.update(request.response_annotations)
                    if cache_key is not None:
                        response_headers[CACHE_STATUS_HEADER] = "miss"
                    return PipelineResult(
                        status=resp.status,
                        body=response_body,
                        headers=response_headers,
                        reason=resp.reason,
                    )
            except aiohttp.ClientError as e:
                next_body = self._next_routing_attempt(request, attempt_body, retry_models)
                if next_body is not None:
                    logger.warning(
                        "Upstream connection error; retrying next routed model",
                        extra={"provider": target.provider, "error": str(e)},
                    )
                    blocked = await self._scan_request(request, next_body)
                    if blocked is not None:
                        return blocked
                    attempt_body = next_body
                    continue
                duration = time.monotonic() - attempt_start
                self._metrics.record_request(target.provider, request.method, 502, duration)
                logger.error(f"Upstream error: {e}")
                return _json_result(502, {
                    "error": {"type": "upstream_error", "message": str(e)}
                })

    def _next_routing_attempt(
        self, request: PipelineRequest, attempt_body: bytes, retry_models: list[str]
    ) -> bytes | None:
        """Pop the next fallback model and return the rewritten body, or None.

        Returns None when no fallback model remains or the body can't be
        rewritten (so the caller treats the current response as final).
        """
        if not retry_models:
            return None
        next_model = retry_models.pop(0)
        rewritten = rewrite_model(attempt_body, next_model)
        if rewritten is None:
            return None
        request.response_annotations[ROUTED_MODEL_HEADER] = sanitize_header_value(
            next_model
        )
        # Keep usage-telemetry provenance in sync with the model actually served:
        # a 5xx fallback changes the routed model, so the prior decision is stale.
        if request.routed_target_model is not None:
            request.routed_target_model = next_model
        self._metrics.record_routing("alias", "fallback")
        return rewritten

    def _build_forward_headers(self, request: PipelineRequest) -> dict[str, str]:
        """Select headers to forward upstream, including exactly one auth header."""
        headers = {}
        for key in FORWARDED_HEADERS:
            if key in request.headers:
                headers[key] = request.headers[key]

        # Forward auth header based on upstream config, with fallbacks
        auth_headers_to_check = list(AUTH_HEADER_FALLBACKS)
        if request.target.auth_header:
            # Prioritize the configured auth header
            configured = request.target.auth_header.lower()
            auth_headers_to_check = [configured] + [
                h for h in auth_headers_to_check if h != configured
            ]
        for key in auth_headers_to_check:
            if key in request.headers:
                headers[key] = request.headers[key]
                break  # Only forward one auth header

        return headers

    async def _scan_response(
        self, request: PipelineRequest, response_body: bytes
    ) -> PipelineResult | None:
        """Scan the upstream response. Returns a result if it must be blocked."""
        config = self._config
        response_scanner = self._scanner.response_scanner
        if not (response_scanner and response_scanner.enabled and response_body):
            return None

        try:
            response_text = response_body.decode("utf-8")
        except UnicodeDecodeError:
            # Binary response, skip scanning
            return None

        scan_start = time.monotonic()
        try:
            # Run CPU-bound scanning in thread pool with timeout
            timeout_s = config.security.scanner_timeout_ms / 1000.0
            scan_result = await asyncio.wait_for(
                asyncio.to_thread(response_scanner.scan, response_text),
                timeout=timeout_s,
            )
            scan_duration = time.monotonic() - scan_start
            self._metrics.record_scan(
                "response",
                "block" if scan_result.blocked else "allow",
                scan_duration,
            )

            if scan_result.has_detections:
                self._report_detection(
                    event_type="response_detection",
                    category=scan_result.category or "unknown",
                    signature_id=scan_result.signature_id,
                    latency_ms=int(scan_duration * 1000),
                    provider=request.target.provider,
                    endpoint=request.path,
                )

                if scan_result.blocked:
                    self._metrics.record_detection(
                        scan_result.category or "unknown",
                        "block",
                        scan_result.signature_id,
                    )
                    logger.warning(
                        "Response blocked",
                        extra={
                            "category": scan_result.category,
                            "signature_id": scan_result.signature_id,
                            "client_id": request.client_id,
                            "internal_details": scan_result.details,
                        },
                    )
                    # Return generic message - never expose signature patterns
                    return _json_result(502, {
                        "error": {
                            "type": "response_blocked",
                            "code": f"{scan_result.category}_detected",
                            "message": "Response blocked: sensitive content detected",
                            "category": scan_result.category,
                        }
                    })

                # Log non-blocking detections
                self._metrics.record_detection(
                    scan_result.category or "unknown",
                    "warn",
                    scan_result.signature_id,
                )
                logger.warning(
                    "Response detection (non-blocking)",
                    extra={
                        "category": scan_result.category,
                        "signature_id": scan_result.signature_id,
                        "client_id": request.client_id,
                    },
                )
        except asyncio.TimeoutError:
            scan_duration = time.monotonic() - scan_start
            self._metrics.record_scan("response", "timeout", scan_duration)
            logger.warning(
                "Response scanner timeout",
                extra={"timeout_ms": config.security.scanner_timeout_ms},
            )
            # Response scanning always fails open on timeout, independent of
            # failure_mode. A timeout is not a detection, and the upstream
            # response already succeeded (and was billed) -- a slow secondary
            # scan must not convert it into an error. failure_mode governs
            # request admission and response *detections*, not this timeout.
        except Exception as e:
            logger.error(f"Response scanner error: {e}")
            # Same rationale: a scanner error must not drop a successful response.

        return None

    def _report_usage(
        self, request: PipelineRequest, response_body: bytes, status: int, duration: float
    ) -> None:
        """Report provider-billed token usage for a successfully forwarded request.

        Best-effort and strictly off the client response path: this only
        schedules a background task. The cheap gate below avoids touching the
        response body at all when usage reporting is disabled/unregistered, and
        the body is parsed inside the task (not synchronously here), so a large
        response never adds parse latency to the request the client is waiting on.
        """
        if not (200 <= status < 300):
            return
        cp_client = get_client()
        if cp_client is None or not cp_client.usage_reporting_enabled:
            return

        asyncio.create_task(
            self._build_and_report_usage(cp_client, request, response_body, duration)
        )

    async def _build_and_report_usage(
        self, cp_client: Any, request: PipelineRequest, response_body: bytes, duration: float
    ) -> None:
        """Parse the response usage field and buffer a usage event (background)."""
        try:
            response_json = json.loads(response_body)
        except Exception:
            return
        if not isinstance(response_json, dict):
            return

        billed = billed_tokens(response_json)
        if billed is None:
            return

        # The response-reported model is the billed truth (may differ from the
        # requested alias, e.g. gpt-4o -> gpt-4o-2024-08-06)
        model = response_json.get("model")
        if model is not None:
            model = str(model)[:100]

        await cp_client.report_usage(
            provider=request.target.provider,
            endpoint=request.path,
            model=model,
            input_tokens=billed.input_tokens,
            output_tokens=billed.output_tokens,
            latency_ms=int(duration * 1000),
            requested_model=request.requested_model,
            routed_model=request.routed_target_model,
            routing_mode=request.routing_mode,
            cache_read_tokens=billed.cache_read_tokens or None,
        )

    def _cache_policy_ok(self) -> bool:
        """Gate response caching off when the policy handles sensitive data (#307 D3).

        Reads the LIVE policy engine (updated by control-plane hot pushes), not the
        static startup config — so enabling PII/PHI detection at runtime disables
        caching immediately. The categories dict only holds enabled categories, so
        presence == on.
        """
        categories = self._policy.categories or {}
        return "pii" not in categories and "phi" not in categories

    def _schedule_cache_store(
        self, cache_key: str, response_body: bytes, content_type: str, status: int
    ) -> None:
        """Fire-and-forget store of a cacheable response (keeps Redis off the response path)."""
        asyncio.create_task(self._cache_store(cache_key, response_body, content_type, status))

    async def _cache_store(
        self, cache_key: str, response_body: bytes, content_type: str, status: int
    ) -> None:
        # Stash billed tokens + model alongside the body so a future hit can
        # attribute the avoided spend (savings telemetry lands in #307 phase 2).
        input_tokens = output_tokens = 0
        model = None
        try:
            response_json = json.loads(response_body)
            if isinstance(response_json, dict):
                raw_model = response_json.get("model")
                model = str(raw_model)[:100] if raw_model is not None else None
                billed = billed_tokens(response_json)
                if billed is not None:
                    input_tokens, output_tokens = billed.input_tokens, billed.output_tokens
        except Exception:
            pass
        await self._cache.set(
            cache_key,
            CachedResponse(
                body=response_body,
                content_type=content_type,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                model=model,
                status=status,
            ),
        )

    def _report_detection(self, **kwargs: Any) -> None:
        """Fire-and-forget detection report to the control plane (if connected)."""
        cp_client = get_client()
        if cp_client:
            asyncio.create_task(cp_client.report_detection(**kwargs))
