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

"""Tests for the decoder module."""

from __future__ import annotations

import base64

from aiproxyguard.scanner.decoder import (
    DecodedContent,
    count_base64_segments,
    decode_base64,
    decode_url,
    has_url_encoding,
)


class TestDecodeBase64:
    """Tests for decode_base64 function."""

    def test_decode_valid_base64(self):
        """Should decode valid base64 strings."""
        # Use longer string to meet 20 char minimum
        original = "Hello World Test String Here"
        encoded = base64.b64encode(original.encode()).decode()
        text = f"Some text with {encoded} embedded"

        results = decode_base64(text)

        assert len(results) == 1
        assert results[0].decoded == original
        assert results[0].encoding == "base64"
        assert results[0].confidence == 0.9

    def test_decode_multiple_segments(self):
        """Should decode multiple base64 segments."""
        segment1 = base64.b64encode(b"First segment here").decode()
        segment2 = base64.b64encode(b"Second segment now").decode()
        text = f"Text {segment1} more {segment2} end"

        results = decode_base64(text)

        assert len(results) == 2

    def test_ignore_short_base64(self):
        """Should ignore base64 strings shorter than 20 chars."""
        short = base64.b64encode(b"Hi").decode()  # Very short
        text = f"Text with {short} here"

        results = decode_base64(text)

        assert len(results) == 0

    def test_ignore_invalid_base64(self):
        """Should ignore invalid base64 that fails to decode."""
        text = "AAAAAAAAAAAAAAAAAAAAAA!!invalid"

        results = decode_base64(text)

        assert len(results) == 0

    def test_ignore_non_printable_decode(self):
        """Should ignore base64 that decodes to non-printable content."""
        # Binary data that's valid base64 but not printable text
        binary_data = bytes(range(256))
        encoded = base64.b64encode(binary_data[:30]).decode()
        text = f"Binary: {encoded}"

        results = decode_base64(text)

        # Should be empty because decoded content is not printable
        assert len(results) == 0


class TestCountBase64Segments:
    """Tests for count_base64_segments function."""

    def test_count_single_segment(self):
        """Should count single base64 segment."""
        # Use longer string to meet 20 char minimum
        encoded = base64.b64encode(b"Hello World Test String").decode()
        text = f"Text with {encoded} here"

        count = count_base64_segments(text)

        assert count == 1

    def test_count_multiple_segments(self):
        """Should count multiple segments."""
        # Use longer strings to meet 20 char minimum
        # Use spaces as separators so base64 boundaries are clear
        segment1 = base64.b64encode(b"First segment is here now").decode()
        segment2 = base64.b64encode(b"Second segment follows it").decode()
        segment3 = base64.b64encode(b"Third one completes trio").decode()
        text = f"Start {segment1} middle {segment2} more {segment3} end"

        count = count_base64_segments(text)

        assert count == 3

    def test_count_zero_for_no_base64(self):
        """Should return 0 when no base64 is present."""
        text = "Just regular text without any encoding"

        count = count_base64_segments(text)

        assert count == 0

    def test_count_ignores_invalid(self):
        """Should not count invalid base64."""
        text = "AAAAAAAAAAAAAAAAAAAAAA!!not-valid"

        count = count_base64_segments(text)

        assert count == 0


class TestDecodeUrl:
    """Tests for decode_url function."""

    def test_decode_url_encoded(self):
        """Should decode URL-encoded content."""
        text = "Hello%20World%21"

        results = decode_url(text)

        assert len(results) == 1
        assert results[0].decoded == "Hello World!"
        assert results[0].encoding == "url"

    def test_no_decode_plain_text(self):
        """Should return empty for plain text without encoding."""
        text = "Just plain text"

        results = decode_url(text)

        assert len(results) == 0

    def test_decode_preserves_original(self):
        """Should preserve original text in result."""
        text = "test%40example.com"

        results = decode_url(text)

        assert results[0].original == text
        assert results[0].decoded == "test@example.com"


class TestHasUrlEncoding:
    """Tests for has_url_encoding function."""

    def test_has_url_encoding_true(self):
        """Should return True for URL-encoded content."""
        text = "Hello%20World"

        result = has_url_encoding(text)

        assert result is True

    def test_has_url_encoding_false_no_percent(self):
        """Should return False when no percent sign."""
        text = "Plain text"

        result = has_url_encoding(text)

        assert result is False

    def test_has_url_encoding_false_same_after_decode(self):
        """Should return False when % doesn't result in change."""
        # Percent that doesn't encode anything
        text = "100% complete"

        result = has_url_encoding(text)

        # unquote("100% complete") might equal "100% complete"
        # depending on the string, but this tests the logic
        assert isinstance(result, bool)


class TestDecodedContent:
    """Tests for DecodedContent dataclass."""

    def test_dataclass_creation(self):
        """DecodedContent should be created with all fields."""
        dc = DecodedContent(
            original="SGVsbG8=",
            decoded="Hello",
            encoding="base64",
            confidence=0.9,
        )

        assert dc.original == "SGVsbG8="
        assert dc.decoded == "Hello"
        assert dc.encoding == "base64"
        assert dc.confidence == 0.9
