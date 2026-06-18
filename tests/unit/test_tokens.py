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

"""Tests for token counting module."""

from aiproxyguard.tokens import count_tokens


class TestCountTokens:
    """Tests for count_tokens function."""

    def test_count_tokens_simple_text(self):
        """Test counting tokens in simple text."""
        result = count_tokens("Hello, world!")
        assert result is not None
        assert isinstance(result, int)
        assert result > 0

    def test_count_tokens_with_known_model(self):
        """Test counting with a known OpenAI model."""
        result = count_tokens("Hello, world!", model="gpt-4o")
        assert result is not None
        assert isinstance(result, int)
        assert result > 0

    def test_count_tokens_with_unknown_model(self):
        """Test fallback to cl100k_base for unknown models."""
        result = count_tokens("Hello, world!", model="some-unknown-model")
        assert result is not None
        assert isinstance(result, int)
        assert result > 0

    def test_count_tokens_empty_string(self):
        """Test that empty string returns None."""
        result = count_tokens("")
        assert result is None

    def test_count_tokens_none_model(self):
        """Test with None model uses fallback."""
        result = count_tokens("Hello, world!", model=None)
        assert result is not None
        assert isinstance(result, int)

    def test_count_tokens_consistency(self):
        """Test that same input produces same output."""
        text = "The quick brown fox jumps over the lazy dog."
        result1 = count_tokens(text, model="gpt-4o")
        result2 = count_tokens(text, model="gpt-4o")
        assert result1 == result2

    def test_count_tokens_longer_text_has_more_tokens(self):
        """Test that longer text has more tokens."""
        short = count_tokens("Hi")
        long = count_tokens("Hello, this is a much longer piece of text that should have more tokens.")
        assert short is not None
        assert long is not None
        assert long > short


class TestBilledTokens:
    """Tests for billed_tokens extraction from response usage fields."""

    def test_openai_shape(self):
        from aiproxyguard.tokens import billed_tokens

        result = billed_tokens({
            "id": "chatcmpl-1",
            "model": "gpt-4o-2024-08-06",
            "usage": {"prompt_tokens": 12, "completion_tokens": 34, "total_tokens": 46},
        })
        assert result is not None
        assert result.input_tokens == 12
        assert result.output_tokens == 34

    def test_anthropic_shape(self):
        from aiproxyguard.tokens import billed_tokens

        result = billed_tokens({
            "id": "msg_1",
            "model": "claude-sonnet-4-5",
            "usage": {"input_tokens": 7, "output_tokens": 21},
        })
        assert result is not None
        assert result.input_tokens == 7
        assert result.output_tokens == 21
        assert result.cache_read_tokens == 0  # absent -> 0

    def test_anthropic_cache_read_tokens(self):
        from aiproxyguard.tokens import billed_tokens

        result = billed_tokens({
            "id": "msg_1",
            "model": "claude-sonnet-4-5",
            # input_tokens EXCLUDES cache reads (Anthropic reports them apart).
            "usage": {
                "input_tokens": 7,
                "output_tokens": 21,
                "cache_read_input_tokens": 500,
            },
        })
        assert result is not None
        assert result.input_tokens == 7
        assert result.cache_read_tokens == 500

    def test_invalid_cache_read_tokens_coerced_to_zero(self):
        from aiproxyguard.tokens import billed_tokens

        result = billed_tokens({
            "usage": {"input_tokens": 7, "output_tokens": 21, "cache_read_input_tokens": -5},
        })
        assert result is not None
        assert result.cache_read_tokens == 0

    def test_openai_cached_tokens_ignored(self):
        # OpenAI's cached_tokens is a subset of prompt_tokens with a different
        # discount; we don't surface it (would double-count / misprice).
        from aiproxyguard.tokens import billed_tokens

        result = billed_tokens({
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "prompt_tokens_details": {"cached_tokens": 80},
            },
        })
        assert result is not None
        assert result.cache_read_tokens == 0

    def test_missing_usage_returns_none(self):
        from aiproxyguard.tokens import billed_tokens

        assert billed_tokens({"id": "chatcmpl-1", "choices": []}) is None

    def test_error_body_returns_none(self):
        from aiproxyguard.tokens import billed_tokens

        assert billed_tokens({"error": {"message": "invalid key"}}) is None

    def test_malformed_usage_returns_none(self):
        from aiproxyguard.tokens import billed_tokens

        assert billed_tokens({"usage": "lots"}) is None
        assert billed_tokens({"usage": {"prompt_tokens": "12", "completion_tokens": 3}}) is None
        assert billed_tokens({"usage": {"prompt_tokens": 12}}) is None

    def test_bool_values_rejected(self):
        from aiproxyguard.tokens import billed_tokens

        assert billed_tokens({"usage": {"prompt_tokens": True, "completion_tokens": False}}) is None

    def test_zero_tokens_valid(self):
        from aiproxyguard.tokens import billed_tokens

        result = billed_tokens({"usage": {"input_tokens": 0, "output_tokens": 0}})
        assert result is not None
        assert result.input_tokens == 0
        assert result.output_tokens == 0


class TestBilledTokensNegative:
    def test_negative_rejected(self):
        from aiproxyguard.tokens import billed_tokens
        assert billed_tokens({"usage": {"prompt_tokens": -1, "completion_tokens": 5}}) is None
        assert billed_tokens({"usage": {"input_tokens": 3, "output_tokens": -2}}) is None
