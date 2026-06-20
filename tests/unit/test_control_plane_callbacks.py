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

"""Tests for shared control-plane callback registration.

Both transports (HTTP server and TLS intercept proxy) wire their config-update
callbacks through register_control_plane_callbacks(), so a new callback type is
added in exactly one place and the two paths cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import MagicMock

from aiproxyguard.server import register_control_plane_callbacks

# Every control-plane callback setter the proxy is expected to register.
# If a new config-update callback is added, it must be wired here (and thus on
# both transports) or this test fails.
EXPECTED_SETTERS = {
    "set_policy_update_callback",
    "set_signature_update_callback",
    "set_ml_model_callback",
    "set_model_sync_begin_callback",
    "set_logging_update_callback",
    "set_scanner_update_callback",
    "set_ml_config_update_callback",
    "set_security_update_callback",
}


@dataclass
class FakeSecurity:
    failure_mode: str = "open"
    scanner_timeout_ms: int = 100


@dataclass
class FakeSignatures:
    path: str = "/nonexistent/signatures"


@dataclass
class FakeCostOpt:
    anthropic_prompt_cache: bool = False
    response_cache: bool = False
    response_cache_routes: list = field(default_factory=list)


@dataclass
class FakeConfig:
    security: FakeSecurity = field(default_factory=FakeSecurity)
    signatures: FakeSignatures = field(default_factory=FakeSignatures)
    cost_optimization: FakeCostOpt = field(default_factory=FakeCostOpt)


def _register(on_signatures_reloaded=None) -> MagicMock:
    cp_client = MagicMock()
    register_control_plane_callbacks(
        cp_client,
        scanner=MagicMock(),
        policy=MagicMock(),
        config=FakeConfig(),
        metrics=MagicMock(),
        on_signatures_reloaded=on_signatures_reloaded,
    )
    return cp_client


def _registered_setters(cp_client: MagicMock) -> set[str]:
    return {
        name
        for name in dir(cp_client)
        if name.startswith("set_")
        and name.endswith("_callback")
        and getattr(cp_client, name).called
    }


class TestCallbackRegistration:
    def test_all_expected_callbacks_registered(self) -> None:
        cp_client = _register()
        assert _registered_setters(cp_client) == EXPECTED_SETTERS

    def test_each_setter_called_exactly_once(self) -> None:
        cp_client = _register()
        for setter in EXPECTED_SETTERS:
            assert getattr(cp_client, setter).call_count == 1, setter

    def test_initial_signature_version_attempted(self) -> None:
        # get_signature_version returns None for a missing path, so the setter
        # is not called -- but registration must not raise.
        cp_client = _register()
        assert cp_client.set_policy_update_callback.called

    def test_signature_reload_hook_invoked(self) -> None:
        """The HTTP path's app-cache hook fires when signatures hot-reload."""
        seen = []
        cp_client = _register(on_signatures_reloaded=seen.append)

        # Pull out the signature-update callback that was registered and invoke it
        sig_cb = cp_client.set_signature_update_callback.call_args.args[0]
        new_sigs = MagicMock()
        new_sigs.signatures = []
        sig_cb(new_sigs)

        assert seen == [new_sigs]

    def test_reload_hook_optional(self) -> None:
        """TLS path passes no hook; signature reload must still work."""
        cp_client = _register(on_signatures_reloaded=None)
        sig_cb = cp_client.set_signature_update_callback.call_args.args[0]
        new_sigs = MagicMock()
        new_sigs.signatures = []
        sig_cb(new_sigs)  # must not raise

    def test_model_sync_begin_resets_scanner_tier(self) -> None:
        """#69: the begin callback must clear the scanner's highest-tier-wins
        state so a fresh sync pass re-decides (and a downgrade takes effect)."""
        cp_client = MagicMock()
        scanner = MagicMock()
        register_control_plane_callbacks(
            cp_client,
            scanner=scanner,
            policy=MagicMock(),
            config=FakeConfig(),
            metrics=MagicMock(),
        )
        begin_cb = cp_client.set_model_sync_begin_callback.call_args.args[0]
        assert begin_cb is scanner.reset_active_ml_tier
        begin_cb()
        assert scanner.reset_active_ml_tier.called


class TestCostOptimizationHandler:
    """The cost_optimization section handler must coerce string booleans (a
    pushed "false"/"0" must disable, not enable via bool()-truthiness)."""

    def _cost_handler(self, cfg):
        cp_client = MagicMock()
        register_control_plane_callbacks(
            cp_client, scanner=MagicMock(), policy=MagicMock(),
            config=cfg, metrics=MagicMock(),
        )
        # pull the handler registered for the "cost_optimization" section
        for call in cp_client.register_section_handler.call_args_list:
            if call.args and call.args[0] == "cost_optimization":
                return call.args[1]
        raise AssertionError("cost_optimization handler not registered")

    def test_string_false_disables(self):
        cfg = FakeConfig(cost_optimization=FakeCostOpt(anthropic_prompt_cache=True))
        handler = self._cost_handler(cfg)
        handler({"anthropic_prompt_cache": "false"})
        assert cfg.cost_optimization.anthropic_prompt_cache is False

    def test_string_true_enables(self):
        cfg = FakeConfig(cost_optimization=FakeCostOpt(anthropic_prompt_cache=False))
        handler = self._cost_handler(cfg)
        handler({"anthropic_prompt_cache": "true"})
        assert cfg.cost_optimization.anthropic_prompt_cache is True

    def test_real_bool_true_enables(self):
        cfg = FakeConfig(cost_optimization=FakeCostOpt(anthropic_prompt_cache=False))
        handler = self._cost_handler(cfg)
        handler({"anthropic_prompt_cache": True})
        assert cfg.cost_optimization.anthropic_prompt_cache is True

    def test_response_cache_string_true_enables(self):
        cfg = FakeConfig(cost_optimization=FakeCostOpt(response_cache=False))
        handler = self._cost_handler(cfg)
        handler({"response_cache": "true"})
        assert cfg.cost_optimization.response_cache is True

    def test_response_cache_string_false_disables(self):
        cfg = FakeConfig(cost_optimization=FakeCostOpt(response_cache=True))
        handler = self._cost_handler(cfg)
        handler({"response_cache": "false"})
        assert cfg.cost_optimization.response_cache is False

    def test_response_cache_independent_of_prompt_cache(self):
        # Pushing only response_cache must not disturb anthropic_prompt_cache.
        cfg = FakeConfig(cost_optimization=FakeCostOpt(anthropic_prompt_cache=True))
        handler = self._cost_handler(cfg)
        handler({"response_cache": True})
        assert cfg.cost_optimization.response_cache is True
        assert cfg.cost_optimization.anthropic_prompt_cache is True

    def test_response_cache_routes_pushed(self):
        cfg = FakeConfig(cost_optimization=FakeCostOpt())
        handler = self._cost_handler(cfg)
        handler({"response_cache_routes": ["/openai/*", "/anthropic/v1/messages"]})
        assert cfg.cost_optimization.response_cache_routes == ["/openai/*", "/anthropic/v1/messages"]

    def test_response_cache_routes_non_list_preserves_existing(self):
        # A malformed (non-list) value must NOT widen scope: keep the current
        # allowlist rather than resetting it to "cache all".
        cfg = FakeConfig(cost_optimization=FakeCostOpt(response_cache_routes=["/openai/*"]))
        handler = self._cost_handler(cfg)
        handler({"response_cache_routes": "nonsense"})
        assert cfg.cost_optimization.response_cache_routes == ["/openai/*"]
