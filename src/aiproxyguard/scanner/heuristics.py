from __future__ import annotations
import unicodedata
from dataclasses import dataclass
from aiproxyguard.scanner.decoder import decode_base64, decode_url


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

        b64_decoded = decode_base64(text)
        if b64_decoded:
            matches.append(HeuristicMatch(
                heuristic="base64_encoding",
                description="Base64 encoded content detected",
                confidence=0.8,
                details=f"Found {len(b64_decoded)} encoded segments",
            ))

        url_decoded = decode_url(text)
        if url_decoded:
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
