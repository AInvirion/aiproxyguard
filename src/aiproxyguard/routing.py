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

"""Smart model routing — phase 1a (explicit ``router:<task>`` aliases).

A client opts in per request by sending ``model: "router:<task>"``. The proxy
resolves the task's cheapest-first ``ordered_pool`` (resolved by the control
plane via its pricing data) to the first *capable* model, rewrites the
``model`` field before forwarding, and records the choice in the
``x-aiproxyguard-routed-model`` response header. On an upstream 5xx the pipeline
retries the next model in the plan (remaining pool, then fallback list).

Selection is pricing-agnostic here: the control plane orders the pool by cost,
so the proxy just walks it. Same-provider pools only (cross-provider payload
translation is out of scope).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aiproxyguard.logging import get_logger

logger = get_logger("routing")

ROUTER_PREFIX = "router:"
ROUTED_MODEL_HEADER = "x-aiproxyguard-routed-model"
# Dry-run decision header for transparent downgrades (#305 1b): reports the
# would-be route without rewriting the model, for validation before enabling.
ROUTING_DECISION_HEADER = "x-aiproxyguard-routing-decision"

# Request features that a cheaper pool member may not support, or that make a
# downgrade unsafe. When present, routing prefers the author-designated
# ``fallback`` models (assumed capable) over the cheapest pool member. Checked
# against the parsed request body.
_EXCLUSION_KEYS = (
    "tools",
    "functions",
    "tool_choice",
    "parallel_tool_calls",
    "response_format",
)


@dataclass
class RoutingDecision:
    """The resolved model plus the ordered fallback plan for 5xx retries."""

    chosen: str
    retry_plan: list[str] = field(default_factory=list)


def parse_router_task(model: Any) -> str | None:
    """Return the task name if ``model`` is a ``router:<task>`` alias, else None."""
    if not isinstance(model, str) or not model.startswith(ROUTER_PREFIX):
        return None
    task = model[len(ROUTER_PREFIX):].strip()
    return task or None


def _has_multimodal_content(body_json: dict[str, Any]) -> bool:
    """True if any message carries non-text content parts (image/audio/file/...).

    Covers both the OpenAI and Anthropic content-block shapes: a ``content``
    that is a list with any part whose ``type`` is not ``text``.
    """
    messages = body_json.get("messages")
    if not isinstance(messages, list):
        return False
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") not in (None, "text"):
                    return True
    return False


def capability_ok(body_json: dict[str, Any]) -> bool:
    """Whether the request is safe to route to the cheapest pool member.

    Returns False when the request uses features a cheaper model may not
    support or that make a downgrade risky: tool/function calling,
    ``response_format``, streaming, or multimodal content. A False result does
    not block routing — it makes the resolver prefer the ``fallback`` models.
    """
    for key in _EXCLUSION_KEYS:
        if body_json.get(key) is not None:
            return False
    if body_json.get("stream"):
        return False
    if _has_multimodal_content(body_json):
        return False
    return True


def select_route(task_cfg: dict[str, Any], capable: bool) -> RoutingDecision | None:
    """Pick the model to route to plus the ordered retry plan.

    ``task_cfg`` is the served task config: ``ordered_pool`` (cheapest-first,
    resolved by the control plane) and an optional ``fallback`` list.

    - ``capable`` request: candidates are pool-then-fallback (cheapest wins).
    - **not** ``capable`` (tools/response_format/multimodal/stream present):
      candidates are the ``fallback`` list ONLY — the author-designated capable
      models. We have no per-model capability metadata, so routing such a
      request to an arbitrary cheap pool member could break it; fail closed
      (return None → 400) when no fallback is configured rather than guess.

    Returns None if no usable candidate models result (caller fails closed).
    """
    pool = [m for m in (task_cfg.get("ordered_pool") or []) if isinstance(m, str)]
    fallback = [m for m in (task_cfg.get("fallback") or []) if isinstance(m, str)]
    candidates = (pool + fallback) if capable else fallback

    seen: set[str] = set()
    ordered: list[str] = []
    for m in candidates:
        if m not in seen:
            seen.add(m)
            ordered.append(m)
    if not ordered:
        return None
    return RoutingDecision(chosen=ordered[0], retry_plan=ordered[1:])


def select_downgrade(
    model: str, provider: str, downgrades: list[Any], eligible: bool
) -> str | None:
    """Pick the cheaper target model for a transparent downgrade, or None.

    Returns the ``to`` model of the first downgrade pair matching the request's
    provider and current ``model`` -- but only when the complexity scorer marked
    the request ``eligible`` (a simple/trivial tier). Same-provider only.
    """
    if not eligible:
        return None
    for pair in downgrades:
        if not isinstance(pair, dict):
            continue
        if pair.get("provider") == provider and pair.get("from") == model:
            to = pair.get("to")
            if isinstance(to, str) and to.strip():
                return to.strip()
    return None


def sanitize_header_value(value: str) -> str:
    """Strip CR/LF (and other controls) so a config-derived model name can't
    split the raw HTTP/1.1 response in the TLS transport. Bounded length."""
    cleaned = "".join(ch for ch in value if ch.isprintable() and ch not in "\r\n")
    return cleaned[:200]


def rewrite_model(body_bytes: bytes, model: str) -> bytes | None:
    """Return ``body_bytes`` with the top-level ``model`` set to ``model``.

    Returns None if the body is not a JSON object (retrying with a different
    model is pointless when the model field can't be rewritten).
    """
    try:
        body = json.loads(body_bytes)
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    body["model"] = model
    return json.dumps(body).encode()
