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

"""Unit tests for the smart-routing pure helpers (#305 phase 1a)."""

from __future__ import annotations

import json

from aiproxyguard.routing import (
    capability_ok,
    parse_router_task,
    rewrite_model,
    sanitize_header_value,
    select_downgrade,
    select_route,
)


class TestParseRouterTask:
    def test_router_prefix_extracts_task(self) -> None:
        assert parse_router_task("router:summarize") == "summarize"

    def test_strips_whitespace(self) -> None:
        assert parse_router_task("router: summarize ") == "summarize"

    def test_non_router_model_is_none(self) -> None:
        assert parse_router_task("gpt-4o") is None

    def test_empty_task_is_none(self) -> None:
        assert parse_router_task("router:") is None
        assert parse_router_task("router:   ") is None

    def test_non_string_is_none(self) -> None:
        assert parse_router_task(None) is None
        assert parse_router_task(123) is None


class TestCapabilityOk:
    def test_plain_request_is_capable(self) -> None:
        assert capability_ok({"model": "gpt-4o", "messages": []}) is True

    def test_excluded_keys_block(self) -> None:
        for key in (
            "tools",
            "functions",
            "tool_choice",
            "parallel_tool_calls",
            "response_format",
        ):
            assert capability_ok({key: ["x"]}) is False, key

    def test_stream_blocks(self) -> None:
        assert capability_ok({"stream": True}) is False
        # falsy stream is fine
        assert capability_ok({"stream": False}) is True

    def test_multimodal_content_blocks(self) -> None:
        body = {
            "messages": [
                {"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}
            ]
        }
        assert capability_ok(body) is False

    def test_text_content_blocks_are_capable(self) -> None:
        body = {
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hi"}]}
            ]
        }
        assert capability_ok(body) is True

    def test_string_content_is_capable(self) -> None:
        body = {"messages": [{"role": "user", "content": "hello"}]}
        assert capability_ok(body) is True


class TestSelectRoute:
    def test_capable_picks_cheapest_pool_first(self) -> None:
        cfg = {"ordered_pool": ["mini", "mid", "max"], "fallback": ["max"]}
        d = select_route(cfg, capable=True)
        assert d is not None
        assert d.chosen == "mini"
        # retry plan = remaining pool then fallback, deduped
        assert d.retry_plan == ["mid", "max"]

    def test_not_capable_uses_fallback_only(self) -> None:
        # not capable -> only author-designated fallback models, never the pool
        cfg = {"ordered_pool": ["mini", "mid"], "fallback": ["max", "max2"]}
        d = select_route(cfg, capable=False)
        assert d is not None
        assert d.chosen == "max"
        assert d.retry_plan == ["max2"]

    def test_not_capable_without_fallback_fails_closed(self) -> None:
        cfg = {"ordered_pool": ["mini", "mid"]}
        assert select_route(cfg, capable=False) is None

    def test_dedupes_preserving_order(self) -> None:
        cfg = {"ordered_pool": ["a", "b"], "fallback": ["b", "a", "c"]}
        d = select_route(cfg, capable=True)
        assert d is not None
        assert d.chosen == "a"
        assert d.retry_plan == ["b", "c"]

    def test_empty_pool_returns_none(self) -> None:
        assert select_route({}, capable=True) is None
        assert select_route({"ordered_pool": [], "fallback": []}, capable=False) is None

    def test_ignores_non_string_entries(self) -> None:
        cfg = {"ordered_pool": ["a", 5, None], "fallback": [{"x": 1}]}
        d = select_route(cfg, capable=True)
        assert d is not None
        assert d.chosen == "a"
        assert d.retry_plan == []


class TestRewriteModel:
    def test_rewrites_model_field(self) -> None:
        out = rewrite_model(b'{"model": "old", "messages": []}', "new")
        assert out is not None
        assert json.loads(out)["model"] == "new"
        assert json.loads(out)["messages"] == []

    def test_non_json_returns_none(self) -> None:
        assert rewrite_model(b"not json", "new") is None

    def test_non_object_returns_none(self) -> None:
        assert rewrite_model(b'["a", "b"]', "new") is None


class TestSelectDowngrade:
    PAIRS = [
        {"provider": "openai", "from": "gpt-4o", "to": "gpt-4o-mini"},
        {"provider": "anthropic", "from": "claude-x", "to": "claude-haiku"},
    ]

    def test_eligible_match_returns_target(self):
        assert select_downgrade("gpt-4o", "openai", self.PAIRS, True) == "gpt-4o-mini"

    def test_not_eligible_returns_none(self):
        assert select_downgrade("gpt-4o", "openai", self.PAIRS, False) is None

    def test_provider_mismatch_returns_none(self):
        assert select_downgrade("gpt-4o", "anthropic", self.PAIRS, True) is None

    def test_model_not_in_pairs_returns_none(self):
        assert select_downgrade("gpt-4o-mini", "openai", self.PAIRS, True) is None

    def test_trims_target(self):
        pairs = [{"provider": "openai", "from": "a", "to": " b "}]
        assert select_downgrade("a", "openai", pairs, True) == "b"


class TestSanitizeHeaderValue:
    def test_strips_crlf(self) -> None:
        assert sanitize_header_value("gpt-4o\r\nX-Evil: 1") == "gpt-4oX-Evil: 1"

    def test_passes_clean_value(self) -> None:
        assert sanitize_header_value("gpt-4o-mini") == "gpt-4o-mini"

    def test_bounded_length(self) -> None:
        assert len(sanitize_header_value("a" * 500)) == 200
