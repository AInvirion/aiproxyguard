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

import pytest

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
