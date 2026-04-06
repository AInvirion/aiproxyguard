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

"""Token counting for telemetry cost savings calculation."""

from __future__ import annotations

import tiktoken

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


def count_tokens(text: str, model: str | None = None) -> int | None:
    """Count tokens in text using tiktoken.

    Args:
        text: The text to count tokens for.
        model: Optional model name to determine encoding.
               Falls back to cl100k_base if unknown.

    Returns:
        Token count, or None if counting fails or text is empty.
    """
    if not text:
        return None

    try:
        encoding_name = ENCODING_MAP.get(model or "", "cl100k_base")
        if encoding_name not in _encoding_cache:
            _encoding_cache[encoding_name] = tiktoken.get_encoding(encoding_name)
        encoding = _encoding_cache[encoding_name]
        return len(encoding.encode(text))
    except Exception:
        return None
