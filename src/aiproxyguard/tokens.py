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

"""Token accounting.

Two distinct concerns, never to be conflated:

- ``count_tokens()`` is a tiktoken-based ESTIMATE. It is only accurate for the
  OpenAI models in ``ENCODING_MAP`` and falls back to ``cl100k_base`` for
  everything else (including Anthropic models, whose tokenizer differs). Use it
  for telemetry on blocked requests, where no provider-billed count can exist.
  Never use it for enforcement (budgets, routing thresholds).

- ``billed_tokens()`` extracts the actual token counts the provider reports in
  the response ``usage`` field. This is what providers bill. Use it for any
  accounting that feeds dashboards, budgets, or savings math.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import tiktoken

from aiproxyguard.logging import get_logger

logger = get_logger("tokens")

# Model -> tiktoken encoding mapping
# OpenAI GPT-4/3.5/embeddings use cl100k_base
ENCODING_MAP: dict[str, str] = {
    "gpt-4": "cl100k_base",
    "gpt-4o": "cl100k_base",
    "gpt-4o-mini": "cl100k_base",
    "gpt-4-turbo": "cl100k_base",
    "gpt-4-turbo-preview": "cl100k_base",
    "gpt-3.5-turbo": "cl100k_base",
    "gpt-3.5-turbo-16k": "cl100k_base",
    "text-embedding-ada-002": "cl100k_base",
    "text-embedding-3-small": "cl100k_base",
    "text-embedding-3-large": "cl100k_base",
}

# Cache for encoding objects
_encoding_cache: dict[str, tiktoken.Encoding] = {}

# Models we've already warned about falling back for (avoid log spam)
_fallback_warned: set[str] = set()


def count_tokens(text: str, model: str | None = None) -> int | None:
    """ESTIMATE the token count of text using tiktoken.

    Only accurate for OpenAI models present in ENCODING_MAP; all other models
    (including Anthropic) fall back to cl100k_base and the count is a rough
    heuristic. Never use this value for enforcement -- see billed_tokens()
    for provider-billed counts.

    Args:
        text: The text to count tokens for.
        model: Optional model name to determine encoding.
               Falls back to cl100k_base if unknown.

    Returns:
        Estimated token count, or None if counting fails or text is empty.
    """
    if not text:
        return None

    try:
        if model and model not in ENCODING_MAP and model not in _fallback_warned:
            _fallback_warned.add(model)
            logger.info(
                "Token estimate falling back to cl100k_base for unrecognized model",
                extra={"model": model},
            )
        encoding_name = ENCODING_MAP.get(model or "", "cl100k_base")
        if encoding_name not in _encoding_cache:
            _encoding_cache[encoding_name] = tiktoken.get_encoding(encoding_name)
        encoding = _encoding_cache[encoding_name]
        return len(encoding.encode(text))
    except Exception:
        return None


@dataclass
class BilledTokens:
    """Provider-billed token counts extracted from a response usage field."""

    input_tokens: int
    output_tokens: int


def billed_tokens(response_json: dict[str, Any]) -> BilledTokens | None:
    """Extract provider-billed token counts from an LLM response body.

    Supports the two dominant usage shapes:
    - OpenAI-compatible: ``usage.prompt_tokens`` / ``usage.completion_tokens``
      (also used by Azure OpenAI, OpenRouter, vLLM, Ollama's OpenAI endpoint)
    - Anthropic: ``usage.input_tokens`` / ``usage.output_tokens``

    Returns None when the response carries no recognizable usage data
    (errors, streaming chunks, non-chat endpoints) -- callers must treat
    that as "unknown", never as zero.
    """
    usage = response_json.get("usage")
    if not isinstance(usage, dict):
        return None

    # OpenAI-compatible shape (bool is an int subclass; exclude it)
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if (isinstance(prompt, int) and not isinstance(prompt, bool)
            and isinstance(completion, int) and not isinstance(completion, bool)):
        return BilledTokens(input_tokens=prompt, output_tokens=completion)

    # Anthropic shape
    inp = usage.get("input_tokens")
    out = usage.get("output_tokens")
    if (isinstance(inp, int) and not isinstance(inp, bool)
            and isinstance(out, int) and not isinstance(out, bool)):
        return BilledTokens(input_tokens=inp, output_tokens=out)

    return None
