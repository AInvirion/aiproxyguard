from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiproxyguard.signatures.models import Signature, SignatureSet

logger = logging.getLogger(__name__)

# Detect available regex engine with fallback chain:
# 1. Hyperscan (x86_64, ~100x faster)
# 2. google-re2 (ARM64 or when hyperscan unavailable)
# 3. Python re (fallback)

_REGEX_ENGINE: str = "re"

try:
    import hyperscan

    _REGEX_ENGINE = "hyperscan"
    logger.info("Using Hyperscan for high-performance regex matching")
except ImportError:
    try:
        import re2

        _REGEX_ENGINE = "re2"
        logger.info("Using google-re2 for regex matching")
    except ImportError:
        logger.warning("Neither hyperscan nor re2 available, falling back to Python re")


def get_regex_engine() -> str:
    """Return the name of the active regex engine."""
    return _REGEX_ENGINE


@dataclass
class ScanMatch:
    signature: Signature
    matched_pattern: str
    matched_text: str
    start: int
    end: int


class BaseRegexScanner(ABC):
    """Abstract base class for regex scanners."""

    def __init__(self, signatures: SignatureSet) -> None:
        self._signatures = signatures

    @abstractmethod
    def scan(self, text: str) -> list[ScanMatch]:
        """Scan text for pattern matches."""
        ...

    @abstractmethod
    def reload(self, signatures: SignatureSet) -> None:
        """Reload patterns from new signature set."""
        ...


class HyperscanScanner(BaseRegexScanner):
    """High-performance regex scanner using Intel Hyperscan."""

    def __init__(self, signatures: SignatureSet) -> None:
        super().__init__(signatures)
        self._db: hyperscan.Database | None = None  # type: ignore[name-defined]
        self._pattern_map: list[tuple[str, Signature]] = []
        self._compile_database()

    def _compile_database(self) -> None:
        """Compile all patterns into a Hyperscan database."""
        import hyperscan

        patterns = self._signatures.all_patterns()
        if not patterns:
            self._db = None
            self._pattern_map = []
            return

        self._pattern_map = patterns
        expressions: list[bytes] = []
        ids: list[int] = []
        flags: list[int] = []

        for idx, (pattern, _sig) in enumerate(patterns):
            try:
                # Encode pattern and add to compilation list
                expressions.append(pattern.encode("utf-8"))
                ids.append(idx)
                # Use SOM_LEFTMOST to get match start position
                flags.append(
                    hyperscan.HS_FLAG_CASELESS
                    | hyperscan.HS_FLAG_SOM_LEFTMOST
                )
            except Exception as e:
                logger.warning(f"Failed to prepare pattern {pattern!r}: {e}")

        if not expressions:
            self._db = None
            return

        try:
            self._db = hyperscan.Database()
            self._db.compile(
                expressions=expressions,
                ids=ids,
                flags=flags,
            )
            logger.debug(f"Compiled {len(expressions)} patterns into Hyperscan database")
        except hyperscan.error as e:
            logger.error(f"Failed to compile Hyperscan database: {e}")
            self._db = None

    def scan(self, text: str) -> list[ScanMatch]:
        """Scan text using Hyperscan batch matching."""
        import hyperscan

        if self._db is None or not self._pattern_map:
            return []

        matches: list[ScanMatch] = []
        text_bytes = text.encode("utf-8")

        def on_match(
            pattern_id: int,
            start: int,
            end: int,
            flags: int,
            context: list[ScanMatch],
        ) -> None:
            """Callback for each Hyperscan match."""
            if pattern_id < len(self._pattern_map):
                pattern, signature = self._pattern_map[pattern_id]
                matched_text = text_bytes[start:end].decode("utf-8", errors="replace")
                context.append(
                    ScanMatch(
                        signature=signature,
                        matched_pattern=pattern,
                        matched_text=matched_text,
                        start=start,
                        end=end,
                    )
                )

        try:
            scanner = hyperscan.Scanner()
            scanner.scan(self._db, text_bytes, match_handler=on_match, context=matches)
        except hyperscan.error as e:
            logger.error(f"Hyperscan scan error: {e}")

        return matches

    def reload(self, signatures: SignatureSet) -> None:
        """Recompile database with new signatures."""
        self._signatures = signatures
        self._compile_database()


class Re2Scanner(BaseRegexScanner):
    """Regex scanner using google-re2."""

    def __init__(self, signatures: SignatureSet) -> None:
        super().__init__(signatures)
        self._compiled: list[tuple[re2._Regexp, str, Signature]] = []  # type: ignore[name-defined]
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile patterns using re2."""
        import re2

        self._compiled = []
        # Create options for case-insensitive matching
        options = re2.Options()
        options.case_sensitive = False

        for pattern, signature in self._signatures.all_patterns():
            try:
                # re2.compile takes pattern and optional Options
                compiled = re2.compile(pattern, options)
                self._compiled.append((compiled, pattern, signature))
            except re2.error as e:
                logger.warning(f"Failed to compile re2 pattern {pattern!r}: {e}")

    def scan(self, text: str) -> list[ScanMatch]:
        """Scan text using re2."""
        matches: list[ScanMatch] = []
        for compiled, pattern, signature in self._compiled:
            for match in compiled.finditer(text):
                matches.append(
                    ScanMatch(
                        signature=signature,
                        matched_pattern=pattern,
                        matched_text=match.group(),
                        start=match.start(),
                        end=match.end(),
                    )
                )
        return matches

    def reload(self, signatures: SignatureSet) -> None:
        """Recompile patterns with new signatures."""
        self._signatures = signatures
        self._compiled = []
        self._compile_patterns()


class PythonReScanner(BaseRegexScanner):
    """Fallback regex scanner using Python's re module."""

    def __init__(self, signatures: SignatureSet) -> None:
        super().__init__(signatures)
        self._compiled: list[tuple[re.Pattern[str], str, Signature]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile patterns using Python re."""
        self._compiled = []
        for pattern, signature in self._signatures.all_patterns():
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._compiled.append((compiled, pattern, signature))
            except re.error as e:
                logger.warning(f"Failed to compile re pattern {pattern!r}: {e}")

    def scan(self, text: str) -> list[ScanMatch]:
        """Scan text using Python re."""
        matches: list[ScanMatch] = []
        for compiled, pattern, signature in self._compiled:
            for match in compiled.finditer(text):
                matches.append(
                    ScanMatch(
                        signature=signature,
                        matched_pattern=pattern,
                        matched_text=match.group(),
                        start=match.start(),
                        end=match.end(),
                    )
                )
        return matches

    def reload(self, signatures: SignatureSet) -> None:
        """Recompile patterns with new signatures."""
        self._signatures = signatures
        self._compiled = []
        self._compile_patterns()


class RegexScanner(BaseRegexScanner):
    """
    Regex scanner with automatic engine selection.

    Selects the best available engine:
    1. Hyperscan (x86_64) - ~100x faster batch matching
    2. google-re2 (ARM64) - safer and faster than Python re
    3. Python re - fallback when nothing else is available
    """

    def __init__(self, signatures: SignatureSet) -> None:
        super().__init__(signatures)
        self._engine: BaseRegexScanner = self._create_engine(signatures)

    def _create_engine(self, signatures: SignatureSet) -> BaseRegexScanner:
        """Create the best available regex engine."""
        if _REGEX_ENGINE == "hyperscan":
            return HyperscanScanner(signatures)
        elif _REGEX_ENGINE == "re2":
            return Re2Scanner(signatures)
        else:
            return PythonReScanner(signatures)

    @property
    def engine_name(self) -> str:
        """Return the name of the underlying engine."""
        return _REGEX_ENGINE

    def scan(self, text: str) -> list[ScanMatch]:
        """Scan text for pattern matches using the selected engine."""
        return self._engine.scan(text)

    def reload(self, signatures: SignatureSet) -> None:
        """Reload patterns - recompiles the engine database."""
        self._signatures = signatures
        self._engine.reload(signatures)
