from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Signature:
    id: str
    name: str
    category: str
    severity: str
    patterns: list[str]
    action: str
    scan_target: str = "request"  # "request", "response", or "both"

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class SignatureSet:
    signatures: list[Signature] = field(default_factory=list)
    _by_id: dict[str, Signature] = field(default_factory=dict, init=False, repr=False)
    _by_category: dict[str, list[Signature]] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self._by_id = {sig.id: sig for sig in self.signatures}
        self._by_category = {}
        for sig in self.signatures:
            if sig.category not in self._by_category:
                self._by_category[sig.category] = []
            self._by_category[sig.category].append(sig)

    def get(self, signature_id: str) -> Signature | None:
        return self._by_id.get(signature_id)

    def by_category(self, category: str) -> list[Signature]:
        return self._by_category.get(category, [])

    def all_patterns(self) -> list[tuple[str, Signature]]:
        result = []
        for sig in self.signatures:
            for pattern in sig.patterns:
                result.append((pattern, sig))
        return result
