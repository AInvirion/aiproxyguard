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

"""Deterministic request-complexity scorer for transparent routing (#305 1b).

A rule-based scorer (adapted from LiteLLM's 7-dimension approach) classifies a
request's prompt into a complexity tier. Phase 1b uses the tier to decide
whether a request that did NOT opt into a router alias is simple enough to
serve from a cheaper same-provider model. Deterministic by design: no inference
latency, reproducible decisions, auditable per-dimension breakdown -- and it
ships behind dry-run so decisions are validated before any model is rewritten.

The token-count signal uses the fuzzy ``count_tokens`` estimate (#311 caveat:
non-OpenAI models fall back to cl100k_base); it is only a soft signal here,
never a hard threshold.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from aiproxyguard.tokens import count_tokens

# Tier boundaries on the combined 0..1 score.
TIER_BOUNDARIES = (0.15, 0.35, 0.60)
# Tiers below this are eligible for a cheaper-model downgrade.
DOWNGRADE_TIERS = frozenset({"trivial", "simple"})

_REASONING_MARKERS = (
    "step by step", "step-by-step", "reason through", "reasoning", "prove",
    "explain why", "think through", "chain of thought", "derive", "work out",
    "justify", "walk me through",
)
_TECHNICAL_TERMS = (
    "algorithm", "complexity", "theorem", "architecture", "concurrency",
    "optimize", "optimization", "asymptotic", "invariant", "race condition",
    "throughput", "latency", "distributed", "cryptograph", "compiler",
    "data structure", "recursion", "big-o", "time complexity",
)
# High-level analysis/design intent. A short prompt asking to compare, design,
# evaluate, etc. is genuinely complex even with few tokens -- its presence
# disqualifies a transparent downgrade (conservative: never downgrade these).
_ANALYSIS_VERBS = (
    "compare", "evaluate", "assess", "design", "architect", "propose",
    "recommend", "trade-off", "tradeoff", "migration", "strategy", "critique",
    "pros and cons", "analyze", "analyse", "plan for", "weigh",
)
_SIMPLE_INDICATORS = (
    "hello", "hi ", "hey", "thanks", "thank you", "translate", "summarize",
    "tl;dr", "what time", "define ", "what is the capital", "say ",
)
_CODE_FENCE = re.compile(r"```")
_CODE_HINTS = re.compile(
    r"\b(def |class |import |function |const |let |var |public |private |"
    r"#include|SELECT |INSERT |=>|console\.log|print\()",
)
_MULTISTEP = re.compile(
    r"(\bstep\s*\d|\b\d+\.\s|\bfirst\b.*\bthen\b|\bnext\b.*\bthen\b|"
    r"\bfinally\b)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class ComplexityScore:
    score: float
    tier: str
    breakdown: dict[str, float] = field(default_factory=dict)
    reasoning_markers: int = 0
    # Any concrete complexity indicator (code, reasoning/analysis verbs,
    # technical terms, multi-step). A request is downgrade-eligible only when it
    # is both low-scoring AND signal-free -- so a short-but-complex prompt
    # ("compare these architectures") is never transparently downgraded.
    has_complexity_signal: bool = False

    @property
    def downgrade_eligible(self) -> bool:
        return self.tier in DOWNGRADE_TIERS and not self.has_complexity_signal


def _count_occurrences(text: str, needles: tuple[str, ...]) -> int:
    return sum(text.count(n) for n in needles)


def extract_prompt_text(body_json: dict[str, Any]) -> str:
    """Best-effort concatenation of the prompt text from a request body.

    Handles OpenAI chat ``messages`` (string or content-block content),
    Anthropic ``system`` + ``messages``, and a legacy ``prompt`` string.
    """
    parts: list[str] = []
    system = body_json.get("system")
    if isinstance(system, str):
        parts.append(system)
    elif isinstance(system, list):
        for block in system:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])

    prompt = body_json.get("prompt")
    if isinstance(prompt, str):
        parts.append(prompt)

    messages = body_json.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                        parts.append(block["text"])
    return "\n".join(parts)


def score_text(text: str, model: str | None = None) -> ComplexityScore:
    """Score a prompt's complexity into a tier with a per-dimension breakdown."""
    lower = text.lower()

    tokens = count_tokens(text, model) or 0
    token_score = min(tokens / 2000.0, 1.0)

    has_code = bool(_CODE_FENCE.search(text) or _CODE_HINTS.search(text))
    code_score = 1.0 if has_code else 0.0

    reasoning_n = _count_occurrences(lower, _REASONING_MARKERS)
    reasoning_score = min(reasoning_n / 2.0, 1.0)

    technical_n = _count_occurrences(lower, _TECHNICAL_TERMS)
    technical_score = min(technical_n / 3.0, 1.0)

    analysis_n = _count_occurrences(lower, _ANALYSIS_VERBS)
    analysis_score = min(analysis_n / 1.0, 1.0)

    simple_n = _count_occurrences(lower, _SIMPLE_INDICATORS)
    simple_score = min(simple_n / 2.0, 1.0)  # negative signal (subtracted)

    multistep_score = 1.0 if _MULTISTEP.search(text) else 0.0

    questions = text.count("?")
    deep_q = _count_occurrences(lower, ("how ", "why "))
    question_score = min((questions + deep_q) / 3.0, 1.0)

    has_complexity_signal = bool(
        has_code or reasoning_n or technical_n or analysis_n or multistep_score
    )

    breakdown = {
        "tokens": round(token_score, 3),
        "code": code_score,
        "reasoning": round(reasoning_score, 3),
        "technical": round(technical_score, 3),
        "analysis": round(analysis_score, 3),
        "simple": round(simple_score, 3),
        "multistep": multistep_score,
        "question": round(question_score, 3),
    }

    # Weighted blend; simple indicators pull the score down.
    raw = (
        0.15 * token_score
        + 0.20 * code_score
        + 0.20 * reasoning_score
        + 0.15 * technical_score
        + 0.20 * analysis_score
        + 0.10 * multistep_score
        + 0.10 * question_score
        - 0.15 * simple_score
    )
    score = max(0.0, min(raw, 1.0))

    # Hard override: 2+ distinct reasoning markers always means a strong model.
    if reasoning_n >= 2:
        return ComplexityScore(
            score=max(score, TIER_BOUNDARIES[2]),
            tier="strong",
            breakdown=breakdown,
            reasoning_markers=reasoning_n,
            has_complexity_signal=True,
        )

    low, mid, high = TIER_BOUNDARIES
    if score < low:
        tier = "trivial"
    elif score < mid:
        tier = "simple"
    elif score < high:
        tier = "moderate"
    else:
        tier = "strong"

    return ComplexityScore(
        score=round(score, 3), tier=tier, breakdown=breakdown,
        reasoning_markers=reasoning_n, has_complexity_signal=has_complexity_signal,
    )
