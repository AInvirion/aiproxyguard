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

from __future__ import annotations
import base64
import re
import urllib.parse
from dataclasses import dataclass


@dataclass
class DecodedContent:
    original: str
    decoded: str
    encoding: str
    confidence: float


# Pre-compiled pattern for base64 detection
_B64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')


def decode_base64(text: str) -> list[DecodedContent]:
    """Decode base64 segments - returns full DecodedContent for detailed analysis."""
    results: list[DecodedContent] = []
    for match in _B64_PATTERN.finditer(text):
        candidate = match.group()
        try:
            decoded = base64.b64decode(candidate).decode('utf-8')
            if decoded.isprintable():
                results.append(DecodedContent(
                    original=candidate, decoded=decoded, encoding="base64", confidence=0.9
                ))
        except Exception:
            pass
    return results


def count_base64_segments(text: str) -> int:
    """Count base64 segments without storing decoded content - O(1) memory."""
    count = 0
    for match in _B64_PATTERN.finditer(text):
        candidate = match.group()
        try:
            decoded = base64.b64decode(candidate).decode('utf-8')
            if decoded.isprintable():
                count += 1
        except Exception:
            pass
    return count


def decode_url(text: str) -> list[DecodedContent]:
    """Decode URL-encoded content - returns full DecodedContent for detailed analysis."""
    results: list[DecodedContent] = []
    if '%' in text:
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                results.append(DecodedContent(
                    original=text, decoded=decoded, encoding="url", confidence=0.8
                ))
        except Exception:
            pass
    return results


def has_url_encoding(text: str) -> bool:
    """Check if text contains URL encoding without storing decoded content."""
    if '%' not in text:
        return False
    try:
        decoded = urllib.parse.unquote(text)
        return decoded != text
    except Exception:
        return False


# Zero-width characters that can be used to split words
ZERO_WIDTH_CHARS = frozenset([
    '\u200b',  # Zero Width Space
    '\u200c',  # Zero Width Non-Joiner
    '\u200d',  # Zero Width Joiner
    '\u2060',  # Word Joiner
    '\ufeff',  # Zero Width No-Break Space (BOM)
    '\u180e',  # Mongolian Vowel Separator
])


def has_zero_width_chars(text: str) -> int:
    """Count zero-width characters in text."""
    return sum(1 for c in text if c in ZERO_WIDTH_CHARS)


def strip_zero_width(text: str) -> str:
    """Remove zero-width characters from text."""
    return ''.join(c for c in text if c not in ZERO_WIDTH_CHARS)


# Pre-compiled pattern for hex escapes like \x69\x67\x6e
_HEX_ESCAPE_PATTERN = re.compile(r'\\x([0-9a-fA-F]{2})')


def has_hex_escapes(text: str) -> bool:
    """Check if text contains hex escape sequences."""
    return bool(_HEX_ESCAPE_PATTERN.search(text))


def decode_hex_escapes(text: str) -> str:
    """Decode hex escape sequences like \\x69 -> 'i'."""
    def replace_hex(match: re.Match) -> str:
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)
    return _HEX_ESCAPE_PATTERN.sub(replace_hex, text)


def decode_rot13(text: str) -> str:
    """Decode ROT13 encoded text."""
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)


def strip_non_letters(text: str) -> str:
    """Strip all non-letter characters to detect hidden words.

    This catches evasion techniques like:
    - I.G.N.O.R.E -> IGNORE
    - i🚨g🚨n🚨o🚨r🚨e -> ignore
    - i-g-n-o-r-e -> ignore
    """
    return ''.join(c for c in text if c.isalpha())
