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
import re
from dataclasses import dataclass
from aiproxyguard.scanner.decoder import (
    count_base64_segments,
    has_url_encoding,
    has_zero_width_chars,
    strip_zero_width,
    has_hex_escapes,
    decode_hex_escapes,
    decode_rot13,
    strip_non_letters,
)


@dataclass
class HeuristicMatch:
    heuristic: str
    description: str
    confidence: float
    details: str


class HeuristicsScanner:
    CONFUSABLES = {
        'а': 'a',
        'е': 'e',
        'і': 'i',
        'о': 'o',
        'р': 'p',
        'с': 'c',
        'у': 'y',
        'х': 'x',
    }

    # Suspicious keywords to detect in decoded/stripped text
    SUSPICIOUS_PATTERNS = [
        re.compile(r'ignore\s*(all\s*)?(previous|prior|above)\s*(instructions?|prompts?|rules?)', re.IGNORECASE),
        re.compile(r'disregard\s*(all\s*)?(previous|prior|above)', re.IGNORECASE),
        re.compile(r'forget\s*(all\s*)?(previous|prior|above)', re.IGNORECASE),
        re.compile(r'(do\s*anything\s*now|DAN\s*mode|jailbreak)', re.IGNORECASE),
        re.compile(r'(system\s*prompt|reveal\s*instructions?)', re.IGNORECASE),
    ]

    def __init__(self, max_length: int = 50000) -> None:
        self.max_length = max_length

    def _check_suspicious_patterns(self, text: str) -> str | None:
        """Check if text matches any suspicious patterns."""
        for pattern in self.SUSPICIOUS_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(0)
        return None

    def scan(self, text: str) -> list[HeuristicMatch]:
        matches: list[HeuristicMatch] = []

        if len(text) > self.max_length:
            matches.append(HeuristicMatch(
                heuristic="excessive_length",
                description="Input exceeds maximum length",
                confidence=1.0,
                details=f"Length {len(text)} > {self.max_length}",
            ))

        b64_count = count_base64_segments(text)
        if b64_count > 0:
            matches.append(HeuristicMatch(
                heuristic="base64_encoding",
                description="Base64 encoded content detected",
                confidence=0.8,
                details=f"Found {b64_count} encoded segments",
            ))

        if has_url_encoding(text):
            matches.append(HeuristicMatch(
                heuristic="url_encoding",
                description="URL encoded content detected",
                confidence=0.6,
                details="Content appears URL encoded",
            ))

        confusable_count = sum(1 for c in text if c in self.CONFUSABLES)
        if confusable_count > 0:
            matches.append(HeuristicMatch(
                heuristic="unicode_obfuscation",
                description="Unicode lookalike characters detected",
                confidence=0.7,
                details=f"Found {confusable_count} confusable characters",
            ))

        # Zero-width character detection
        zw_count = has_zero_width_chars(text)
        if zw_count > 0:
            matches.append(HeuristicMatch(
                heuristic="zero_width_chars",
                description="Zero-width characters detected",
                confidence=0.75,
                details=f"Found {zw_count} zero-width characters",
            ))
            stripped = strip_zero_width(text)
            if found := self._check_suspicious_patterns(stripped):
                matches.append(HeuristicMatch(
                    heuristic="zero_width_evasion",
                    description="Suspicious content hidden with zero-width chars",
                    confidence=0.9,
                    details=f"Hidden: {found}",
                ))

        # Hex escape detection
        if has_hex_escapes(text):
            matches.append(HeuristicMatch(
                heuristic="hex_escapes",
                description="Hex escape sequences detected",
                confidence=0.7,
                details="Text contains \\xNN sequences",
            ))
            decoded = decode_hex_escapes(text)
            if found := self._check_suspicious_patterns(decoded):
                matches.append(HeuristicMatch(
                    heuristic="hex_escape_evasion",
                    description="Suspicious content hidden with hex escapes",
                    confidence=0.9,
                    details=f"Hidden: {found}",
                ))

        # Compute letters_only once for reuse in multiple checks
        letters_only = strip_non_letters(text)
        has_significant_noise = len(letters_only) < len(text) * 0.85

        # ROT13 detection - try both original and letters-only
        # This catches both clean ROT13 and noisy ROT13 (with digits/emoji mixed in)
        for rot13_input in [text, letters_only] if has_significant_noise else [text]:
            if len(rot13_input) < 10:  # Too short to be meaningful
                continue
            rot13_decoded = decode_rot13(rot13_input)
            if found := self._check_suspicious_patterns(rot13_decoded):
                matches.append(HeuristicMatch(
                    heuristic="rot13_evasion",
                    description="Suspicious content hidden with ROT13",
                    confidence=0.85,
                    details=f"Hidden: {found}",
                ))
                break  # Only report once

        # Character insertion detection (emoji, punctuation)
        if has_significant_noise:
            if found := self._check_suspicious_patterns(letters_only):
                if not self._check_suspicious_patterns(text):
                    matches.append(HeuristicMatch(
                        heuristic="char_insertion_evasion",
                        description="Suspicious content hidden with char insertion",
                        confidence=0.85,
                        details=f"Hidden: {found}",
                    ))

        return matches
