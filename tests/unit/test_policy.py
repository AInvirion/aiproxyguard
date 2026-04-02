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

    def test_sensitivity_conversion(self) -> None:
        """Sensitivity should convert to threshold (threshold = 1 - sensitivity)."""
        engine = PolicyEngine(
            default_action="block",
            categories={"prompt_injection": {"action": "block", "sensitivity": 0.3}}
        )
        # sensitivity=0.3 → threshold=0.7
        # confidence=0.5 < threshold=0.7 → allow
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.5)

        action = engine.resolve("client1", scan_result)

        assert action == "allow"

    def test_sensitivity_high_blocks(self) -> None:
        """High sensitivity (low threshold) should block more."""
        engine = PolicyEngine(
            default_action="block",
            categories={"prompt_injection": {"action": "block", "sensitivity": 0.9}}
        )
        # sensitivity=0.9 → threshold=0.1
        # confidence=0.5 >= threshold=0.1 → block
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.5)

        action = engine.resolve("client1", scan_result)

        assert action == "block"

    def test_sensitivity_precedence_over_threshold(self) -> None:
        """Sensitivity takes precedence when both are provided."""
        engine = PolicyEngine(
            default_action="block",
            categories={"prompt_injection": {"action": "block", "threshold": 0.9, "sensitivity": 0.3}}
        )
        # sensitivity=0.3 → threshold=0.7 (ignores threshold=0.9)
        # confidence=0.5 < threshold=0.7 → allow
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.5)

        action = engine.resolve("client1", scan_result)

        assert action == "allow"

    def test_sensitivity_boundary_zero(self) -> None:
        """Sensitivity=0 means threshold=1.0 (only block with 100% confidence)."""
        engine = PolicyEngine(
            default_action="block",
            categories={"prompt_injection": {"action": "block", "sensitivity": 0.0}}
        )
        # sensitivity=0.0 → threshold=1.0
        # confidence=0.99 < threshold=1.0 → allow
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.99)

        action = engine.resolve("client1", scan_result)

        assert action == "allow"

    def test_sensitivity_boundary_one(self) -> None:
        """Sensitivity=1 means threshold=0.0 (block everything detected)."""
        engine = PolicyEngine(
            default_action="block",
            categories={"prompt_injection": {"action": "block", "sensitivity": 1.0}}
        )
        # sensitivity=1.0 → threshold=0.0
        # confidence=0.01 >= threshold=0.0 → block
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.01)

        action = engine.resolve("client1", scan_result)

        assert action == "block"

    def test_sensitivity_clamped_above_one(self) -> None:
        """Sensitivity above 1.0 should be clamped to 1.0 (threshold=0.0)."""
        engine = PolicyEngine(
            default_action="block",
            categories={"prompt_injection": {"action": "block", "sensitivity": 1.5}}
        )
        # sensitivity=1.5 clamped to 1.0 → threshold=0.0
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.01)

        action = engine.resolve("client1", scan_result)

        assert action == "block"

    def test_sensitivity_clamped_below_zero(self) -> None:
        """Sensitivity below 0.0 should be clamped to 0.0 (threshold=1.0)."""
        engine = PolicyEngine(
            default_action="block",
            categories={"prompt_injection": {"action": "block", "sensitivity": -0.5}}
        )
        # sensitivity=-0.5 clamped to 0.0 → threshold=1.0
        scan_result = ScanResult(action="block", category="prompt_injection", confidence=0.99)

        action = engine.resolve("client1", scan_result)

        assert action == "allow"


class TestPolicyWithSignatureCategories:
    """Test policy engine with actual signature bundle categories.

    These tests verify the policy engine correctly handles all categories
    defined in the signature bundle (signatures/rules.yaml).
    """

    # All categories from the signature bundle
    SIGNATURE_CATEGORIES = [
        "prompt-injection",
        "jailbreak",
        "encoding-bypass",
        "delimiter-injection",
        "indirect-injection",
        "unicode-evasion",
        "role-manipulation",
    ]

    def test_all_signature_categories_with_default_action(self) -> None:
        """All signature categories should use default action when no override."""
        engine = PolicyEngine(default_action="block", categories={})

        for category in self.SIGNATURE_CATEGORIES:
            scan_result = ScanResult(action="block", category=category, confidence=0.9)
            action = engine.resolve("client1", scan_result)
            assert action == "block", f"Category {category} should use default action"

    def test_per_category_threshold_with_signature_categories(self) -> None:
        """Per-category threshold should work with actual signature categories."""
        engine = PolicyEngine(
            default_action="block",
            categories={
                "prompt-injection": {"action": "block", "threshold": 0.9},
                "jailbreak": {"action": "block", "threshold": 0.8},
                "encoding-bypass": {"action": "warn", "threshold": 0.7},
            }
        )

        # Below threshold → allow
        result1 = ScanResult(action="block", category="prompt-injection", confidence=0.85)
        assert engine.resolve("client1", result1) == "allow"

        # Above threshold → action applies
        result2 = ScanResult(action="block", category="jailbreak", confidence=0.85)
        assert engine.resolve("client1", result2) == "block"

        # Different action per category
        result3 = ScanResult(action="block", category="encoding-bypass", confidence=0.75)
        assert engine.resolve("client1", result3) == "warn"

    def test_per_category_sensitivity_with_signature_categories(self) -> None:
        """Per-category sensitivity should work with actual signature categories."""
        engine = PolicyEngine(
            default_action="block",
            categories={
                "prompt-injection": {"action": "block", "sensitivity": 0.9},  # threshold=0.1
                "jailbreak": {"action": "block", "sensitivity": 0.5},  # threshold=0.5
                "unicode-evasion": {"action": "warn", "sensitivity": 0.3},  # threshold=0.7
            }
        )

        # High sensitivity (low threshold) blocks lower confidence
        result1 = ScanResult(action="block", category="prompt-injection", confidence=0.2)
        assert engine.resolve("client1", result1) == "block"

        # Medium sensitivity allows very low confidence
        result2 = ScanResult(action="block", category="jailbreak", confidence=0.3)
        assert engine.resolve("client1", result2) == "allow"

        # Low sensitivity (high threshold) allows medium confidence
        result3 = ScanResult(action="block", category="unicode-evasion", confidence=0.6)
        assert engine.resolve("client1", result3) == "allow"

    def test_allowlist_with_signature_categories(self) -> None:
        """Allowlist should work with actual signature categories."""
        engine = PolicyEngine(
            default_action="block",
            categories={},
            allowlists=[
                {"client_id": "encoding-test-tool", "categories": ["encoding-bypass"]},
                {"client_id": "security-scanner", "categories": ["*"]},
            ]
        )

        # Specific category allowlist
        result1 = ScanResult(action="block", category="encoding-bypass", confidence=0.9)
        assert engine.resolve("encoding-test-tool", result1) == "allow"

        # Same client, different category - not allowlisted
        result2 = ScanResult(action="block", category="prompt-injection", confidence=0.9)
        assert engine.resolve("encoding-test-tool", result2) == "block"

        # Wildcard allowlist
        result3 = ScanResult(action="block", category="indirect-injection", confidence=0.9)
        assert engine.resolve("security-scanner", result3) == "allow"

    def test_mixed_threshold_and_sensitivity_per_category(self) -> None:
        """Different categories can use threshold or sensitivity independently."""
        engine = PolicyEngine(
            default_action="block",
            categories={
                "prompt-injection": {"action": "block", "threshold": 0.8},  # explicit threshold
                "jailbreak": {"action": "block", "sensitivity": 0.7},  # sensitivity → threshold=0.3
                "delimiter-injection": {"action": "warn", "threshold": 0.6},
                "indirect-injection": {"action": "log", "sensitivity": 0.4},  # threshold=0.6
            }
        )

        # threshold=0.8, confidence=0.7 → allow
        r1 = ScanResult(action="block", category="prompt-injection", confidence=0.7)
        assert engine.resolve("client1", r1) == "allow"

        # sensitivity=0.7 → threshold=0.3, confidence=0.5 → block
        r2 = ScanResult(action="block", category="jailbreak", confidence=0.5)
        assert engine.resolve("client1", r2) == "block"

        # threshold=0.6, confidence=0.7 → warn
        r3 = ScanResult(action="block", category="delimiter-injection", confidence=0.7)
        assert engine.resolve("client1", r3) == "warn"

        # sensitivity=0.4 → threshold=0.6, confidence=0.5 → allow
        r4 = ScanResult(action="block", category="indirect-injection", confidence=0.5)
        assert engine.resolve("client1", r4) == "allow"
