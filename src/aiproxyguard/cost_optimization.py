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

"""Token-cost-optimization request mutators.

Phase 1: Anthropic prompt-cache injection. Adds
``cache_control: {"type": "ephemeral"}`` to the top-level ``system`` prompt of
Anthropic Messages-API requests so Anthropic caches that prefix and bills the
cached portion at a discount on subsequent requests.

These run as body mutators in the shared request pipeline (parse -> mutate ->
serialize -> scan -> forward), so the scanner always inspects the mutated
payload that is actually forwarded.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urlparse

if TYPE_CHECKING:
    from aiproxyguard.config import Config
    from aiproxyguard.pipeline import UpstreamTarget

from aiproxyguard.logging import get_logger

logger = get_logger("cost_optimization")

# Anthropic provider name as resolved by the router / TLS host map.
_ANTHROPIC_PROVIDER = "anthropic"

_EPHEMERAL = {"type": "ephemeral"}


def _is_anthropic_messages(target: "UpstreamTarget") -> bool:
    """True only for an Anthropic-bound Messages API request.

    cache_control on a top-level ``system`` is a Messages API construct; scope
    to it explicitly rather than relying on the body shape alone, so other
    Anthropic endpoints (now or future) are never rewritten.
    """
    if target.provider.lower() != _ANTHROPIC_PROVIDER:
        return False
    path = urlparse(target.url).path.rstrip("/")
    return path.endswith("/messages")


def inject_anthropic_cache_control(
    body_json: dict[str, Any], target: "UpstreamTarget"
) -> "dict[str, Any] | None":
    """Add cache_control to the top-level Anthropic ``system`` prompt.

    Phase 1 scope: only a top-level ``system`` that is a non-empty **string**
    is handled -- it is rewritten to the content-block form with an ephemeral
    cache_control marker:

        "system": "You are ..."
        -> "system": [{"type": "text", "text": "You are ...",
                       "cache_control": {"type": "ephemeral"}}]

    Returns the mutated dict, or ``None`` for "no change" when:
    - the request is not an Anthropic Messages API request,
    - there is no top-level ``system`` string (e.g. it is already a content
      block array -- left untouched until phase 2 -- or absent, as in the
      legacy Text Completions API which uses ``prompt``),
    - the system string is empty.

    Note: Anthropic silently ignores cache_control on prefixes below the
    per-model minimum token count, so injecting on a short system prompt is
    harmless (it simply won't be cached).
    """
    if not _is_anthropic_messages(target):
        return None

    system = body_json.get("system")
    if not isinstance(system, str) or not system.strip():
        # Not a top-level system string: array form (phase 2) or absent.
        return None

    body_json["system"] = [
        {"type": "text", "text": system, "cache_control": dict(_EPHEMERAL)}
    ]
    logger.debug(
        "Anthropic prompt cache_control injected into system prompt",
        extra={"provider": target.provider},
    )
    return body_json


def make_cache_control_mutator(
    config: "Config",
) -> Callable[[dict[str, Any], "UpstreamTarget"], "dict[str, Any] | None"]:
    """Build a pipeline mutator gated on the live cost-optimization config.

    The returned closure reads ``config.cost_optimization.anthropic_prompt_cache``
    on every call, so the control plane can toggle the feature at runtime via
    the pushed ``cost_optimization`` config section without a restart.
    """

    def mutator(
        body_json: dict[str, Any], target: "UpstreamTarget"
    ) -> "dict[str, Any] | None":
        if not config.cost_optimization.anthropic_prompt_cache:
            return None
        return inject_anthropic_cache_control(body_json, target)

    return mutator
