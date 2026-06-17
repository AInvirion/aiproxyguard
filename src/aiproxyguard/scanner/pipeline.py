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
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from aiproxyguard.config import MLClassifierConfig, ScannerConfig
    from aiproxyguard.signatures.models import SignatureSet
from aiproxyguard.logging import get_logger
from aiproxyguard.scanner.regex import RegexScanner
from aiproxyguard.scanner.heuristics import HeuristicsScanner
from aiproxyguard.scanner.response import ResponseScanner, ResponseScanResult
from aiproxyguard.scanner.ml import MLClassifier

logger = get_logger("scanner.pipeline")

# Relative precedence of model tiers. The control plane sends an account every
# tier it is entitled to (e.g. an enterprise account gets free+pro+enterprise),
# and models arrive in bundle order. Without precedence, a lower-tier model
# applied later would overwrite a higher one, so an enterprise account could
# end up running the pro model. We keep the highest tier active.
_ML_TIER_RANK = {"free": 0, "pro": 1, "enterprise": 2}


def normalize_category_slug(category: str) -> str:
    """Normalize category slug to use hyphens (standard format).

    Converts underscores to hyphens for consistency:
    - prompt_injection -> prompt-injection
    - encoding_bypass -> encoding-bypass
    """
    return category.replace("_", "-")


@dataclass
class ScanResult:
    action: str  # allow, log, warn, block
    category: str | None = None
    signature_id: str | None = None
    confidence: float = 0.0
    details: str | None = None
    matches: list[str] | None = None


class ScannerPipeline:
    def __init__(
        self,
        config: ScannerConfig,
        signatures: SignatureSet,
        ml_config: MLClassifierConfig | None = None,
    ) -> None:
        self._config = config
        self._signatures = signatures
        self._regex_scanner: RegexScanner | None = None
        self._heuristics_scanner: HeuristicsScanner | None = None
        self._response_scanner: ResponseScanner | None = None
        self._ml_classifier: MLClassifier | None = None
        # Tier rank of the currently-active ML model (-1 = unknown/none).
        # Used to keep the highest entitled tier active across model syncs.
        self._ml_model_tier_rank: int = -1
        if config.regex:
            self._regex_scanner = RegexScanner(signatures)
        if config.heuristics:
            self._heuristics_scanner = HeuristicsScanner()
        if config.response.enabled:
            self._response_scanner = ResponseScanner(config.response, signatures)
        if config.ml_classifier and ml_config is not None:
            self._ml_classifier = MLClassifier(ml_config)

    def scan(self, text: str) -> ScanResult:
        if not self._config.enabled:
            return ScanResult(action="allow")

        action_priority = {"allow": 0, "log": 1, "warn": 2, "block": 3}
        # Track best match in single pass - O(n) instead of O(n log n)
        best: tuple[str, str, str | None, str, float] | None = None
        best_score: tuple[int, float] = (-1, -1.0)
        all_details: list[str] = []

        if self._regex_scanner:
            for match in self._regex_scanner.scan(text):
                internal_detail = f"pattern:{match.matched_pattern}"
                all_details.append(internal_detail)
                # Normalize category slug (child_safety_response -> child-safety-response)
                normalized_category = normalize_category_slug(match.signature.category)
                score = (action_priority.get(match.signature.action, 0), 0.9)
                if score > best_score:
                    best_score = score
                    best = (
                        match.signature.action,
                        normalized_category,
                        match.signature.id,
                        internal_detail,
                        0.9,
                    )

        if self._heuristics_scanner:
            for match in self._heuristics_scanner.scan(text):
                all_details.append(match.description)
                score = (action_priority.get("warn", 0), match.confidence)
                if score > best_score:
                    best_score = score
                    best = ("warn", "encoding-bypass", None, match.description, match.confidence)

        if self._ml_classifier and self._ml_classifier.is_available():
            for match in self._ml_classifier.predict(text):
                # Skip non-threat categories (e.g., "safe", "benign")
                if match.category.lower() in ("safe", "benign", "normal", "clean"):
                    continue
                # Normalize category slug (prompt_injection -> prompt-injection)
                normalized_category = normalize_category_slug(match.category)
                detail = f"ml:{match.model_id}:{normalized_category}:{match.confidence:.2f}"
                all_details.append(detail)
                # Use configured action from MLClassifierConfig
                ml_action = self._ml_classifier._config.action
                score = (action_priority.get(ml_action, 0), match.confidence)
                if score > best_score:
                    best_score = score
                    best = (ml_action, normalized_category, match.model_id, detail, match.confidence)

        if best is None:
            return ScanResult(action="allow")

        return ScanResult(
            action=best[0],
            category=best[1],
            signature_id=best[2],
            confidence=best[4],
            details=best[3],
            matches=all_details,
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

    @property
    def ml_classifier(self) -> MLClassifier | None:
        """Get the ML classifier instance."""
        return self._ml_classifier

    def reload(self, signatures: SignatureSet) -> None:
        self._signatures = signatures
        if self._regex_scanner:
            self._regex_scanner.reload(signatures)
        if self._response_scanner:
            self._response_scanner.reload(signatures)
        # ML classifier reload is handled separately via reload_ml_model

    def reload_ml_model(self, model_path: str | None = None) -> None:
        """Reload the ML model, optionally from a new path."""
        if self._ml_classifier:
            from pathlib import Path
            path = Path(model_path) if model_path else None
            self._ml_classifier.reload(path)

    def reset_active_ml_tier(self) -> None:
        """Reset the active-model tier tracking at the start of a model-sync pass.

        Each signature/model sync re-fetches the full set of bundles the account
        is currently entitled to, so the highest-tier decision must be made fresh
        per pass. Without this reset, a tier *downgrade* (e.g. enterprise -> pro)
        would never take effect at runtime because the previously-active higher
        tier would keep winning. Resetting per pass lets the highest tier among
        the *currently entitled* bundles win.

        Concurrency invariant: ``_ml_model_tier_rank`` is plain mutable state
        with no lock, so this reset and the ``load_ml_from_bytes`` calls that
        follow it must run within a single, non-overlapping sync pass. The
        control plane guarantees this -- signature/model syncs are driven only
        by the single ``_heartbeat_loop`` task (and the one-shot offline cache
        load at startup), so passes are serialized and never interleave. If a
        concurrent sync caller is ever introduced, this state must be guarded
        (e.g. snapshot the entitled bundles and pick the winner under a lock)
        or a mid-pass reset could let a lower tier clobber a higher one.
        """
        self._ml_model_tier_rank = -1

    def load_ml_from_bytes(self, model_data: bytes, model_config: dict | None = None) -> bool:
        """Load ML model from bytes (e.g., from control plane sync).

        Args:
            model_data: Decrypted model bytes from control plane.
            model_config: Optional model metadata (model_id, model_version, etc.)

        Returns:
            True if loading was successful.

        Highest-tier-wins: when the model carries a known ``tier``, a model from
        a lower tier than the currently-active one is skipped, so an account
        entitled to a higher tier keeps that model regardless of the order
        bundles are applied. Same-or-higher tier (including same-tier version
        updates) still loads. Models with no tier info are always applied.
        """
        if self._ml_classifier is None:
            return False

        tier = (model_config or {}).get("tier")
        new_rank = _ML_TIER_RANK.get(tier, -1) if tier else None
        if new_rank is not None and new_rank < self._ml_model_tier_rank:
            logger.info(
                "Skipping lower-tier ML model; keeping higher-tier model active",
                extra={"incoming_tier": tier, "active_tier_rank": self._ml_model_tier_rank},
            )
            return False

        loaded = self._ml_classifier.load_from_bytes(model_data, config=model_config)
        if loaded and new_rank is not None:
            self._ml_model_tier_rank = max(self._ml_model_tier_rank, new_rank)
        return loaded

    def update_scanner_config(self, config: dict) -> None:
        """Update scanner configuration from control plane.

        Args:
            config: Scanner config dict with keys:
                - enabled: Master enable/disable
                - regex: Enable regex scanning
                - heuristics: Enable heuristics scanning
                - ml_classifier: Enable ML classifier
        """
        if "enabled" in config:
            self._config.enabled = config["enabled"]
        if "regex" in config:
            self._config.regex = config["regex"]
        if "heuristics" in config:
            self._config.heuristics = config["heuristics"]
        if "ml_classifier" in config:
            self._config.ml_classifier = config["ml_classifier"]

    def set_request_scanning(self, enabled: bool) -> None:
        """Enable/disable scanning of proxied requests (policy ``scan_request``).

        Toggles the dedicated ``request_scanning`` flag, not the global
        ``enabled`` switch, so disabling it stops inspecting proxied traffic
        while the manual ``/check`` detection endpoint and the global on/off
        remain unaffected.
        """
        self._config.request_scanning = enabled

    def set_response_scanning(self, enabled: bool) -> None:
        """Enable/disable response scanning (policy ``scan_response`` toggle).

        The ResponseScanner only builds its internal scanner when constructed
        with an enabled config, so enabling at runtime reconstructs it (which
        also re-filters response-applicable signatures); disabling drops it.

        Construct first, then commit config + scanner together, so a failed
        reconstruction leaves prior state intact (no enabled-config /
        stale-scanner inconsistency) and the error propagates to the caller's
        per-section isolation.
        """
        if enabled:
            new_response_config = replace(self._config.response, enabled=True)
            scanner = ResponseScanner(new_response_config, self._signatures)
            self._config.response = new_response_config
            self._response_scanner = scanner
        else:
            self._config.response.enabled = False
            self._response_scanner = None

    def update_ml_config(self, config: dict) -> None:
        """Update ML classifier configuration from control plane.

        Args:
            config: ML config dict with keys:
                - threshold: Confidence threshold (0.0-1.0)
                - action: Action on detection (block, warn, log)
        """
        if self._ml_classifier:
            if "threshold" in config:
                self._ml_classifier._config.threshold = config["threshold"]
            if "action" in config:
                self._ml_classifier._config.action = config["action"]
