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

"""Response scanner for detecting sensitive data leakage in LLM responses.

This module implements Phase 4B response scanning with three modes:
- passthrough: No blocking, async alert/log only
- buffered: Scan first N chars before streaming (configurable buffer size)
- full: Complete scan before returning response (blocks streaming)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, AsyncIterator

if TYPE_CHECKING:
    from aiproxyguard.config import ResponseScannerConfig
    from aiproxyguard.signatures.models import SignatureSet

from aiproxyguard.scanner.regex import RegexScanner, ScanMatch
from aiproxyguard.logging import get_logger

logger = get_logger("response_scanner")


class ResponseScanMode(str, Enum):
    """Response scanning modes."""
    PASSTHROUGH = "passthrough"
    BUFFERED = "buffered"
    FULL = "full"


@dataclass
class ResponseScanResult:
    """Result of response content scanning."""

    blocked: bool = False
    matches: list[ScanMatch] = field(default_factory=list)
    category: str | None = None
    signature_id: str | None = None
    details: str | None = None
    scanned_length: int = 0

    @property
    def has_detections(self) -> bool:
        """Check if any matches were detected."""
        return len(self.matches) > 0


class ResponseScanner:
    """
    Scanner for LLM response content to detect sensitive data leakage.

    Supports three scanning modes:
    - passthrough: Non-blocking, logs detections asynchronously
    - buffered: Scans initial buffer before releasing chunks
    - full: Scans complete response before returning
    """

    def __init__(
        self,
        config: ResponseScannerConfig,
        signatures: SignatureSet,
    ) -> None:
        self._config = config
        self._signatures = signatures
        self._scanner: RegexScanner | None = None

        if config.enabled:
            # Filter signatures for response scanning
            self._filtered_signatures = self._filter_response_signatures(signatures)
            if self._filtered_signatures.signatures:
                self._scanner = RegexScanner(self._filtered_signatures)

    def _filter_response_signatures(self, signatures: SignatureSet) -> SignatureSet:
        """Filter signatures that apply to response scanning."""
        from aiproxyguard.signatures.models import SignatureSet as SigSet

        filtered = []
        for sig in signatures.signatures:
            # Check if signature applies to response scanning
            scan_target = getattr(sig, "scan_target", "request")
            if scan_target in ("response", "both"):
                # Also filter by configured categories if specified
                if not self._config.categories or sig.category in self._config.categories:
                    filtered.append(sig)

        return SigSet(signatures=filtered)

    @property
    def mode(self) -> ResponseScanMode:
        """Get current scanning mode."""
        return ResponseScanMode(self._config.mode)

    @property
    def buffer_size(self) -> int:
        """Get buffer size for buffered mode."""
        return self._config.buffer_size

    @property
    def enabled(self) -> bool:
        """Check if response scanning is enabled."""
        return self._config.enabled

    def scan(self, content: str) -> ResponseScanResult:
        """
        Scan response content for sensitive data patterns.

        Args:
            content: Response text to scan

        Returns:
            ResponseScanResult with detection information
        """
        if not self._config.enabled or self._scanner is None:
            return ResponseScanResult(scanned_length=len(content))

        matches = self._scanner.scan(content)

        if not matches:
            return ResponseScanResult(scanned_length=len(content))

        # Determine the highest-severity match
        action_priority = {"allow": 0, "log": 1, "warn": 2, "block": 3}
        sorted_matches = sorted(
            matches,
            key=lambda m: action_priority.get(m.signature.action, 0),
            reverse=True
        )

        top_match = sorted_matches[0]
        should_block = top_match.signature.action == "block"

        return ResponseScanResult(
            blocked=should_block,
            matches=matches,
            category=top_match.signature.category,
            signature_id=top_match.signature.id,
            details=f"Detected: {top_match.matched_pattern}",
            scanned_length=len(content),
        )

    def reload(self, signatures: SignatureSet) -> None:
        """Reload scanner with new signatures."""
        self._signatures = signatures
        self._filtered_signatures = self._filter_response_signatures(signatures)
        if self._filtered_signatures.signatures:
            if self._scanner:
                self._scanner.reload(self._filtered_signatures)
            else:
                self._scanner = RegexScanner(self._filtered_signatures)
        else:
            self._scanner = None


class SSEResponseHandler:
    """
    Handler for Server-Sent Events (SSE) streaming responses.

    Manages buffering and scanning of SSE chunks according to
    the configured scanning mode.
    """

    def __init__(
        self,
        scanner: ResponseScanner,
        on_detection: callable | None = None,
    ) -> None:
        """
        Initialize SSE handler.

        Args:
            scanner: ResponseScanner instance
            on_detection: Optional callback for detection events
        """
        self._scanner = scanner
        self._on_detection = on_detection
        self._buffer: list[str] = []
        self._buffer_length = 0
        self._initial_scan_done = False
        self._full_content: list[str] = []
        self._scan_result: ResponseScanResult | None = None

    def _extract_sse_data(self, chunk: bytes) -> str:
        """Extract data content from SSE chunk."""
        try:
            text = chunk.decode("utf-8")
        except UnicodeDecodeError:
            return ""

        # Extract data from SSE format (data: <content>\n\n)
        content_parts = []
        for line in text.split("\n"):
            if line.startswith("data: "):
                data = line[6:]
                if data != "[DONE]":
                    content_parts.append(data)

        return " ".join(content_parts)

    async def process_chunk(self, chunk: bytes) -> tuple[bytes | None, ResponseScanResult | None]:
        """
        Process a single SSE chunk.

        Args:
            chunk: Raw SSE chunk bytes

        Returns:
            Tuple of (chunk to forward or None, scan result if blocked)
        """
        mode = self._scanner.mode

        if not self._scanner.enabled:
            return chunk, None

        # Extract text content from SSE
        content = self._extract_sse_data(chunk)

        if mode == ResponseScanMode.PASSTHROUGH:
            # Non-blocking: scan asynchronously, always forward
            if content:
                asyncio.create_task(self._async_scan(content))
            return chunk, None

        elif mode == ResponseScanMode.BUFFERED:
            return await self._process_buffered(chunk, content)

        elif mode == ResponseScanMode.FULL:
            return await self._process_full(chunk, content)

        return chunk, None

    async def _async_scan(self, content: str) -> None:
        """Perform async scan and trigger callback on detection."""
        result = self._scanner.scan(content)
        if result.has_detections and self._on_detection:
            await asyncio.to_thread(self._on_detection, result)

    async def _process_buffered(
        self,
        chunk: bytes,
        content: str
    ) -> tuple[bytes | None, ResponseScanResult | None]:
        """Process chunk in buffered mode."""
        if self._initial_scan_done:
            # After initial scan passed, forward chunks directly
            return chunk, None

        # Buffer chunks until we have enough to scan
        self._buffer.append(content)
        self._buffer_length += len(content)

        if self._buffer_length >= self._scanner.buffer_size:
            # Scan the buffered content
            full_buffer = "".join(self._buffer)
            result = self._scanner.scan(full_buffer)

            if result.blocked:
                # Block - return scan result
                return None, result

            # Scan passed - release buffered chunks
            self._initial_scan_done = True

            # Notify about non-blocking detections
            if result.has_detections and self._on_detection:
                asyncio.create_task(asyncio.to_thread(self._on_detection, result))

            return chunk, None

        # Still buffering - don't forward yet
        return None, None

    async def _process_full(
        self,
        chunk: bytes,
        content: str
    ) -> tuple[bytes | None, ResponseScanResult | None]:
        """
        Process chunk in full mode.

        In full mode, we collect all chunks and scan at the end.
        Returns None for chunks during collection.
        """
        self._full_content.append(content)
        # Don't forward anything yet - will be handled by finalize()
        return None, None

    async def finalize(self) -> tuple[list[bytes], ResponseScanResult | None]:
        """
        Finalize processing and return results.

        For buffered mode: Releases any remaining buffered chunks.
        For full mode: Scans complete content and returns result.

        Returns:
            Tuple of (chunks to forward, scan result if blocked)
        """
        mode = self._scanner.mode

        if mode == ResponseScanMode.BUFFERED:
            # If we haven't done initial scan yet (content smaller than buffer)
            if not self._initial_scan_done and self._buffer:
                full_buffer = "".join(self._buffer)
                result = self._scanner.scan(full_buffer)

                if result.blocked:
                    return [], result

                if result.has_detections and self._on_detection:
                    asyncio.create_task(asyncio.to_thread(self._on_detection, result))

            return [], None

        elif mode == ResponseScanMode.FULL:
            # Scan complete content
            full_content = "".join(self._full_content)
            result = self._scanner.scan(full_content)
            self._scan_result = result

            if result.blocked:
                return [], result

            if result.has_detections and self._on_detection:
                asyncio.create_task(asyncio.to_thread(self._on_detection, result))

            return [], None

        return [], None

    def get_buffered_content(self) -> str:
        """Get all buffered/collected content."""
        if self._scanner.mode == ResponseScanMode.FULL:
            return "".join(self._full_content)
        return "".join(self._buffer)


async def scan_streaming_response(
    scanner: ResponseScanner,
    chunks: AsyncIterator[bytes],
    on_detection: callable | None = None,
) -> AsyncIterator[bytes]:
    """
    Scan a streaming response for sensitive data.

    This is a convenience async generator that wraps SSEResponseHandler
    for easy integration with aiohttp streaming.

    Args:
        scanner: ResponseScanner instance
        chunks: Async iterator of response chunks
        on_detection: Optional callback for detection events

    Yields:
        Response chunks (possibly delayed based on scanning mode)

    Raises:
        ResponseBlockedError: If content is blocked in full/buffered mode
    """
    handler = SSEResponseHandler(scanner, on_detection)
    collected_chunks: list[bytes] = []

    async for chunk in chunks:
        result_chunk, scan_result = await handler.process_chunk(chunk)

        if scan_result and scan_result.blocked:
            raise ResponseBlockedError(scan_result)

        if scanner.mode == ResponseScanMode.FULL:
            # Collect chunks for full scan
            collected_chunks.append(chunk)
        elif result_chunk is not None:
            yield result_chunk
        elif scanner.mode == ResponseScanMode.BUFFERED:
            # Store buffered chunks for later release
            collected_chunks.append(chunk)

    # Finalize and release any remaining content
    _, final_result = await handler.finalize()

    if final_result and final_result.blocked:
        raise ResponseBlockedError(final_result)

    # For buffered mode, release collected chunks after initial scan
    # For full mode, release all chunks after complete scan
    if scanner.mode in (ResponseScanMode.BUFFERED, ResponseScanMode.FULL):
        for chunk in collected_chunks:
            yield chunk


class ResponseBlockedError(Exception):
    """Raised when response content is blocked."""

    def __init__(self, scan_result: ResponseScanResult) -> None:
        self.scan_result = scan_result
        super().__init__(f"Response blocked: {scan_result.details}")
