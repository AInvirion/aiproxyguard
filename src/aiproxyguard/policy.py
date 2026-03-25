"""Policy engine for action resolution."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from aiproxyguard.scanner.pipeline import ScanResult


class PolicyEngine:
    """Resolve final action based on policy configuration."""

    def __init__(
        self,
        default_action: str = "block",
        categories: dict[str, dict[str, Any]] | None = None,
        allowlists: list[dict[str, Any]] | None = None,
    ) -> None:
        """Initialize policy engine.

        Args:
            default_action: Default action for unmatched categories
            categories: Per-category action and threshold overrides
            allowlists: Client allowlist configurations
        """
        # Validate action
        VALID_ACTIONS = frozenset({"allow", "log", "warn", "block"})
        if default_action not in VALID_ACTIONS:
            raise ValueError(f"Invalid action: {default_action}. Must be one of: {VALID_ACTIONS}")

        self.default_action = default_action
        self.categories = categories or {}
        self.allowlists = allowlists or []

        # Build allowlist index (merge categories for duplicate client_ids)
        self._allowlist_index: dict[str, set[str]] = {}
        for entry in self.allowlists:
            client_id = entry.get("client_id", "")
            cats = entry.get("categories", [])
            if client_id in self._allowlist_index:
                self._allowlist_index[client_id].update(cats)
            else:
                self._allowlist_index[client_id] = set(cats)

    def resolve(self, client_id: str, scan_result: ScanResult) -> str:
        """Resolve final action for a scan result.

        Args:
            client_id: The resolved client identity
            scan_result: Result from scanner pipeline

        Returns:
            Final action (allow, log, warn, block)
        """
        # If scan result is already allow, nothing to do
        if scan_result.action == "allow":
            return "allow"

        category = scan_result.category or "unknown"
        confidence = scan_result.confidence

        # Check allowlist
        if client_id in self._allowlist_index:
            allowed_cats = self._allowlist_index[client_id]
            if "*" in allowed_cats or category in allowed_cats:
                return "allow"

        # Get category config
        cat_config = self.categories.get(category, {})
        threshold = cat_config.get("threshold", 0.0)
        action = cat_config.get("action", self.default_action)

        # Check threshold
        if confidence < threshold:
            return "allow"

        return action

    def is_allowlisted(self, client_id: str, category: str) -> bool:
        """Check if client is allowlisted for a category."""
        if client_id not in self._allowlist_index:
            return False

        allowed = self._allowlist_index[client_id]
        return "*" in allowed or category in allowed

    def update_config(self, config: dict) -> None:
        """Update policy configuration from control plane.

        Args:
            config: Policy config dict with keys:
                - default_action: Default action for unmatched categories
                - categories: Per-category action and threshold overrides
                - allowlists: Client allowlist configurations
        """
        VALID_ACTIONS = frozenset({"allow", "log", "warn", "block"})

        default_action = config.get("default_action", self.default_action)
        if default_action not in VALID_ACTIONS:
            raise ValueError(f"Invalid action: {default_action}. Must be one of: {VALID_ACTIONS}")

        self.default_action = default_action
        self.categories = config.get("categories", {})
        self.allowlists = config.get("allowlists", [])

        # Rebuild allowlist index
        self._allowlist_index = {}
        for entry in self.allowlists:
            client_id = entry.get("client_id", "")
            cats = entry.get("categories", [])
            if client_id in self._allowlist_index:
                self._allowlist_index[client_id].update(cats)
            else:
                self._allowlist_index[client_id] = set(cats)
