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

"""Tests for policy engine."""

from aiproxyguard.policy import PolicyEngine
from aiproxyguard.scanner.pipeline import ScanResult
import pytest


class TestPolicyEngine:
    """Test policy action resolution."""

    def test_default_action(self) -> None:
        """Use default action when no category override."""
        engine = PolicyEngine(default_action="block", categories={})
        scan_result = ScanResult(action="block", category="unknown", confidence=0.9)

        action = engine.resolve("client1", scan_result)

        assert action == "block"

    def test_category_override(self) -> None:
        """Category-specific action overrides default."""
        engine = PolicyEngine(
            default_action="block",
            categories={"prompt_injection": {"action": "warn", "threshold": 0.5}}
        )
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.9)

        action = engine.resolve("client1", scan_result)

        assert action == "warn"

    def test_threshold_check(self) -> None:
        """Low confidence below threshold becomes allow."""
        engine = PolicyEngine(
            default_action="block",
            categories={"prompt_injection": {"action": "block", "threshold": 0.8}}
        )
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.5)

        action = engine.resolve("client1", scan_result)

        assert action == "allow"

    def test_allowlist_bypasses(self) -> None:
        """Allowlisted clients bypass detection."""
        engine = PolicyEngine(
            default_action="block",
            categories={},
            allowlists=[{"client_id": "admin-tool", "categories": ["*"]}]
        )
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.9)

        action = engine.resolve("admin-tool", scan_result)

        assert action == "allow"

    def test_partial_allowlist(self) -> None:
        """Allowlist only for specific categories."""
        engine = PolicyEngine(
            default_action="block",
            categories={},
            allowlists=[{"client_id": "test-tool", "categories": ["jailbreak"]}]
        )

        # Allowed category
        scan1 = ScanResult(action="block", category="jailbreak", confidence=0.9)
        assert engine.resolve("test-tool", scan1) == "allow"

        # Not allowed category
        scan2 = ScanResult(action="block", category="prompt_injection", confidence=0.9)
        assert engine.resolve("test-tool", scan2) == "block"

    def test_scan_result_allow_returns_allow(self) -> None:
        """If scan result action is already allow, return allow immediately."""
        engine = PolicyEngine(default_action="block", categories={})
        scan_result = ScanResult(action="allow", category="prompt_injection", confidence=0.9)

        action = engine.resolve("client1", scan_result)

        assert action == "allow"

    def test_is_allowlisted_wildcard(self) -> None:
        """Test is_allowlisted with wildcard."""
        engine = PolicyEngine(
            default_action="block",
            categories={},
            allowlists=[{"client_id": "admin", "categories": ["*"]}]
        )

        assert engine.is_allowlisted("admin", "any_category") is True
        assert engine.is_allowlisted("unknown", "any_category") is False

    def test_is_allowlisted_specific(self) -> None:
        """Test is_allowlisted with specific category."""
        engine = PolicyEngine(
            default_action="block",
            categories={},
            allowlists=[{"client_id": "test", "categories": ["jailbreak"]}]
        )

        assert engine.is_allowlisted("test", "jailbreak") is True
        assert engine.is_allowlisted("test", "prompt_injection") is False

    def test_threshold_boundary(self) -> None:
        """Confidence equal to threshold should NOT allow (threshold is exclusive)."""
        engine = PolicyEngine(
            default_action="block",
            categories={"prompt_injection": {"action": "block", "threshold": 0.8}}
        )
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.8)

        action = engine.resolve("client1", scan_result)

        assert action == "block"  # confidence >= threshold means action applies

    def test_invalid_action_raises(self) -> None:
        """Invalid default_action raises ValueError."""
        with pytest.raises(ValueError, match="Invalid action"):
            PolicyEngine(default_action="invalid")

    def test_allowlist_merge(self) -> None:
        """Duplicate client_id entries should merge categories."""
        engine = PolicyEngine(
            default_action="block",
            categories={},
            allowlists=[
                {"client_id": "multi", "categories": ["cat1"]},
                {"client_id": "multi", "categories": ["cat2"]}
            ]
        )

        assert engine.is_allowlisted("multi", "cat1") is True
        assert engine.is_allowlisted("multi", "cat2") is True
