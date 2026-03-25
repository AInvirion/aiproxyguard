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


def decode_base64(text: str) -> list[DecodedContent]:
    results: list[DecodedContent] = []
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    for match in b64_pattern.finditer(text):
        candidate = match.group()
        try:
            decoded = base64.b64decode(candidate).decode('utf-8')
            if decoded.isprintable():
                results.append(DecodedContent(original=candidate, decoded=decoded, encoding="base64", confidence=0.9))
        except Exception:
            pass
    return results


def decode_url(text: str) -> list[DecodedContent]:
    results: list[DecodedContent] = []
    if '%' in text:
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                results.append(DecodedContent(original=text, decoded=decoded, encoding="url", confidence=0.8))
        except Exception:
            pass
    return results
