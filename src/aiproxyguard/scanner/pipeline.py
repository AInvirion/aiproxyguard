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

from __future__ import annotations
import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from aiproxyguard.config import ScannerConfig
    from aiproxyguard.signatures.models import SignatureSet
from aiproxyguard.scanner.regex import RegexScanner
from aiproxyguard.scanner.heuristics import HeuristicsScanner
from aiproxyguard.scanner.response import ResponseScanner, ResponseScanResult


@dataclass
class ScanResult:
    action: str  # allow, log, warn, block
    category: str | None = None
    signature_id: str | None = None
    confidence: float = 0.0
    details: str | None = None
    matches: list[str] | None = None


class ScannerPipeline:
    def __init__(self, config: ScannerConfig, signatures: SignatureSet) -> None:
        self._config = config
        self._signatures = signatures
        self._regex_scanner: RegexScanner | None = None
        self._heuristics_scanner: HeuristicsScanner | None = None
        self._response_scanner: ResponseScanner | None = None
        if config.regex:
            self._regex_scanner = RegexScanner(signatures)
        if config.heuristics:
            self._heuristics_scanner = HeuristicsScanner()
        if config.response.enabled:
            self._response_scanner = ResponseScanner(config.response, signatures)

    def scan(self, text: str) -> ScanResult:
        if not self._config.enabled:
            return ScanResult(action="allow")
        # Format: (action, category, signature_id, internal_details, confidence)
        # internal_details are for logging only, never exposed to clients
        all_matches: list[tuple[str, str, str | None, str, float]] = []
        if self._regex_scanner:
            for match in self._regex_scanner.scan(text):
                # Store pattern internally for server-side logging only
                internal_detail = f"pattern:{match.matched_pattern}"
                all_matches.append((
                    match.signature.action,
                    match.signature.category,
                    match.signature.id,
                    internal_detail,
                    0.9
                ))
        if self._heuristics_scanner:
            for match in self._heuristics_scanner.scan(text):
                all_matches.append(("warn", "encoding_evasion", None, match.description, match.confidence))
        if not all_matches:
            return ScanResult(action="allow")
        action_priority = {"allow": 0, "log": 1, "warn": 2, "block": 3}
        sorted_matches = sorted(all_matches, key=lambda m: (action_priority.get(m[0], 0), m[4]), reverse=True)
        top = sorted_matches[0]
        # details field contains internal info for logging - never expose to clients
        return ScanResult(
            action=top[0],
            category=top[1],
            signature_id=top[2],
            confidence=top[4],
            details=top[3],
            matches=[m[3] for m in all_matches]
        )

    async def scan_async(self, text: str) -> ScanResult:
        """Async version that runs CPU-bound scanning in a thread pool.

        Prevents blocking the event loop during regex matching.
        """
        return await asyncio.to_thread(self.scan, text)

    def scan_response(self, text: str) -> ResponseScanResult:
        """Scan response content for sensitive data leakage."""
        if self._response_scanner is None:
            return ResponseScanResult(scanned_length=len(text))
        return self._response_scanner.scan(text)

    async def scan_response_async(self, text: str) -> ResponseScanResult:
        """Async version that runs CPU-bound response scanning in a thread pool."""
        return await asyncio.to_thread(self.scan_response, text)

    @property
    def response_scanner(self) -> ResponseScanner | None:
        """Get the response scanner instance."""
        return self._response_scanner

    def reload(self, signatures: SignatureSet) -> None:
        self._signatures = signatures
        if self._regex_scanner:
            self._regex_scanner.reload(signatures)
        if self._response_scanner:
            self._response_scanner.reload(signatures)
