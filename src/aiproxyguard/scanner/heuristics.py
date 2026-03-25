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
from dataclasses import dataclass
from aiproxyguard.scanner.decoder import count_base64_segments, has_url_encoding


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

    def __init__(self, max_length: int = 50000) -> None:
        self.max_length = max_length

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

        return matches
