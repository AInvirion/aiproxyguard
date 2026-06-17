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

"""Tests for cost-optimization mutators (#304 Anthropic prompt cache)."""

from __future__ import annotations

from dataclasses import dataclass, field

from aiproxyguard.cost_optimization import (
    inject_anthropic_cache_control,
    make_cache_control_mutator,
)


@dataclass
class FakeTarget:
    provider: str
    url: str = "https://api.anthropic.com/v1/messages"
    auth_header: str | None = "x-api-key"
    timeout: float = 60.0


@dataclass
class FakeCostOpt:
    anthropic_prompt_cache: bool = True


@dataclass
class FakeConfig:
    cost_optimization: FakeCostOpt = field(default_factory=FakeCostOpt)


ANTHROPIC = FakeTarget(provider="anthropic")
OPENAI = FakeTarget(provider="openai", url="https://api.openai.com/v1/chat/completions")
ANTHROPIC_NON_MESSAGES = FakeTarget(
    provider="anthropic", url="https://api.anthropic.com/v1/complete"
)


class TestInjectAnthropicCacheControl:
    def test_top_level_system_string_converted_with_cache_control(self):
        body = {"model": "claude-sonnet-4-5", "system": "You are a helpful assistant.",
                "messages": [{"role": "user", "content": "hi"}]}
        result = inject_anthropic_cache_control(body, ANTHROPIC)

        assert result is not None
        assert result["system"] == [{
            "type": "text",
            "text": "You are a helpful assistant.",
            "cache_control": {"type": "ephemeral"},
        }]
        # other fields untouched
        assert result["model"] == "claude-sonnet-4-5"
        assert result["messages"] == [{"role": "user", "content": "hi"}]

    def test_non_anthropic_provider_is_noop(self):
        body = {"system": "You are helpful.", "messages": []}
        assert inject_anthropic_cache_control(body, OPENAI) is None

    def test_provider_match_is_case_insensitive(self):
        body = {"system": "x" * 10}
        assert inject_anthropic_cache_control(body, FakeTarget(provider="Anthropic")) is not None

    def test_non_messages_anthropic_endpoint_is_noop(self):
        # Only the Messages API uses top-level system + cache_control
        body = {"system": "You are helpful."}
        assert inject_anthropic_cache_control(body, ANTHROPIC_NON_MESSAGES) is None

    def test_no_system_is_noop(self):
        body = {"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "hi"}]}
        assert inject_anthropic_cache_control(body, ANTHROPIC) is None

    def test_empty_system_is_noop(self):
        assert inject_anthropic_cache_control({"system": "   "}, ANTHROPIC) is None

    def test_system_already_array_left_untouched_phase1(self):
        # Array (content-block) form is phase 2 -- must not be touched in phase 1
        body = {"system": [{"type": "text", "text": "already structured"}]}
        assert inject_anthropic_cache_control(body, ANTHROPIC) is None

    def test_idempotent_on_repeat_runs(self):
        body = {"system": "You are helpful and verbose."}
        first = inject_anthropic_cache_control(body, ANTHROPIC)
        assert first is not None
        # system is now an array -> second run is a no-op (no double-injection)
        assert inject_anthropic_cache_control(first, ANTHROPIC) is None


class TestGatedMutator:
    def test_enabled_injects(self):
        mutator = make_cache_control_mutator(FakeConfig(FakeCostOpt(anthropic_prompt_cache=True)))
        result = mutator({"system": "You are helpful."}, ANTHROPIC)
        assert result is not None
        assert result["system"][0]["cache_control"] == {"type": "ephemeral"}

    def test_disabled_is_noop(self):
        mutator = make_cache_control_mutator(FakeConfig(FakeCostOpt(anthropic_prompt_cache=False)))
        assert mutator({"system": "You are helpful."}, ANTHROPIC) is None

    def test_reads_flag_live(self):
        cfg = FakeConfig(FakeCostOpt(anthropic_prompt_cache=False))
        mutator = make_cache_control_mutator(cfg)
        assert mutator({"system": "You are helpful."}, ANTHROPIC) is None
        # control plane flips the flag at runtime
        cfg.cost_optimization.anthropic_prompt_cache = True
        assert mutator({"system": "You are helpful."}, ANTHROPIC) is not None
