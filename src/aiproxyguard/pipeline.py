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

from aiproxyguard.control_plane import get_client
from aiproxyguard.logging import get_logger
from aiproxyguard.metrics import MetricsCollector
from aiproxyguard.policy import PolicyEngine
from aiproxyguard.scanner.pipeline import ScannerPipeline
from aiproxyguard.tokens import count_tokens

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
    ) -> None:
        self._config = config
        self._scanner = scanner
        self._policy = policy
        self._metrics = metrics
        self._session_getter = session_getter
        self._mutators: list[BodyMutator] = []

    def add_mutator(self, mutator: BodyMutator) -> None:
        """Register a body mutator (e.g. prompt cache injection, model routing)."""
        self._mutators.append(mutator)

    async def process(self, request: PipelineRequest) -> PipelineResult:
        """Run a request through mutate -> scan -> forward -> scan response."""
        start_time = time.monotonic()

        outbound = self._apply_mutations(request)

        blocked = await self._scan_request(request, outbound)
        if blocked is not None:
            return blocked

        return await self._forward(request, outbound, start_time)

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
        if not (config.scanner.enabled and outbound):
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
        self, request: PipelineRequest, outbound: bytes, start_time: float
    ) -> PipelineResult:
        """Forward the outbound bytes upstream and scan the response."""
        config = self._config
        target = request.target
        try:
            session = self._session_getter()
            headers = self._build_forward_headers(request)

            async with session.request(
                method=request.method,
                url=target.url,
                headers=headers,
                data=outbound if outbound else None,
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

                duration = time.monotonic() - start_time
                self._metrics.record_request(target.provider, request.method, resp.status, duration)

                blocked = await self._scan_response(request, response_body)
                if blocked is not None:
                    return blocked

                response_headers = {
                    header: resp.headers[header]
                    for header in RESPONSE_HEADERS
                    if header in resp.headers
                }
                return PipelineResult(
                    status=resp.status,
                    body=response_body,
                    headers=response_headers,
                    reason=resp.reason,
                )
        except aiohttp.ClientError as e:
            duration = time.monotonic() - start_time
            self._metrics.record_request(target.provider, request.method, 502, duration)
            logger.error(f"Upstream error: {e}")
            return _json_result(502, {
                "error": {"type": "upstream_error", "message": str(e)}
            })

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

    def _report_detection(self, **kwargs: Any) -> None:
        """Fire-and-forget detection report to the control plane (if connected)."""
        cp_client = get_client()
        if cp_client:
            asyncio.create_task(cp_client.report_detection(**kwargs))
