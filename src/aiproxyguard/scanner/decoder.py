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
