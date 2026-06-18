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

"""Unit tests for the deterministic complexity scorer (#305 1b)."""

from __future__ import annotations

from aiproxyguard.complexity import extract_prompt_text, score_text


class TestScoreText:
    def test_trivial_prompt_is_downgrade_eligible(self):
        s = score_text("hi")
        assert s.tier in ("trivial", "simple")
        assert s.downgrade_eligible is True

    def test_two_reasoning_markers_force_strong(self):
        # hard override regardless of an otherwise short prompt
        s = score_text("Explain why this works and reason through it.")
        assert s.reasoning_markers >= 2
        assert s.tier == "strong"
        assert s.downgrade_eligible is False

    def test_single_reasoning_marker_not_overridden(self):
        s = score_text("Please summarize this.")
        # one or zero markers -> not the hard override path
        assert s.tier != "strong" or s.reasoning_markers < 2

    def test_code_presence_detected(self):
        s = score_text("```python\ndef f():\n    return 1\n```")
        assert s.breakdown["code"] == 1.0

    def test_code_plus_technical_plus_multistep_not_eligible(self):
        text = (
            "Optimize this algorithm for time complexity.\n"
            "```\ndef f(x): return x\n```\n"
            "Step 1: analyze. Step 2: refactor."
        )
        s = score_text(text)
        assert s.downgrade_eligible is False
        assert s.breakdown["code"] == 1.0
        assert s.breakdown["multistep"] == 1.0

    def test_score_bounded_0_1(self):
        s = score_text("algorithm complexity theorem architecture concurrency optimize")
        assert 0.0 <= s.score <= 1.0

    # Short-but-complex prompts must NOT be downgrade-eligible (false-downgrade
    # class). A single analysis/design verb or technical term is a hard signal.
    def test_short_complex_prompts_not_eligible(self):
        for prompt in (
            "compare these two architectures",
            "design a migration plan for a distributed system",
            "evaluate the tradeoffs",
            "analyze this approach",
            "recommend a strategy",
        ):
            s = score_text(prompt)
            assert s.has_complexity_signal is True, prompt
            assert s.downgrade_eligible is False, prompt

    def test_empty_text_has_no_signal(self):
        # empty scores trivial with no signal; the pipeline guards this path
        # separately (fail-closed) so it is never downgraded in practice.
        s = score_text("")
        assert s.has_complexity_signal is False


class TestExtractPromptText:
    def test_combines_system_and_messages(self):
        body = {
            "system": "You are helpful.",
            "messages": [
                {"role": "user", "content": "first"},
                {"role": "assistant", "content": "ok"},
                {"role": "user", "content": [{"type": "text", "text": "second"}]},
            ],
        }
        text = extract_prompt_text(body)
        assert "You are helpful." in text
        assert "first" in text
        assert "second" in text

    def test_legacy_prompt_field(self):
        assert "hello world" in extract_prompt_text({"prompt": "hello world"})

    def test_empty_body(self):
        assert extract_prompt_text({}) == ""
