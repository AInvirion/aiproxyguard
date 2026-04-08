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

import logging
import re
import threading
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

    # Verify hyperscan is actually functional (not just stub bindings)
    # Database class must exist and have compile/scan methods
    if hasattr(hyperscan, "Database"):
        _test_db = hyperscan.Database()
        if hasattr(_test_db, "compile") and hasattr(_test_db, "scan"):
            _REGEX_ENGINE = "hyperscan"
            logger.info("Using Hyperscan for high-performance regex matching")
        else:
            raise ImportError("Hyperscan Database missing compile/scan methods")
        del _test_db
    else:
        raise ImportError("Hyperscan bindings incomplete - missing Database")
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
        # Thread-local storage for scratch spaces to avoid HS_SCRATCH_IN_USE (-10) errors
        self._scratch_local = threading.local()
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
                # HS_FLAG_CASELESS + HS_FLAG_UTF8 for proper Unicode support
                # UTF8 flag is critical for patterns with Unicode character classes
                # (e.g., [Ⓐ-ⓩ] for circled letters) to work correctly
                # Without it, ranges are interpreted as raw byte ranges, causing false positives
                flags.append(hyperscan.HS_FLAG_CASELESS | hyperscan.HS_FLAG_UTF8)
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

    def _get_scratch(self) -> "hyperscan.Scratch | None":  # type: ignore[name-defined]
        """Get or create a thread-local scratch space for the current database."""
        import hyperscan

        if self._db is None:
            return None

        # Check if this thread already has a scratch for the current db
        scratch = getattr(self._scratch_local, "scratch", None)
        db_id = getattr(self._scratch_local, "db_id", None)

        # Create new scratch if none exists or if db was recompiled
        current_db_id = id(self._db)
        if scratch is None or db_id != current_db_id:
            try:
                scratch = hyperscan.Scratch(self._db)
                self._scratch_local.scratch = scratch
                self._scratch_local.db_id = current_db_id
            except hyperscan.error as e:
                logger.error(f"Failed to allocate Hyperscan scratch: {e}")
                return None

        return scratch

    def scan(self, text: str) -> list[ScanMatch]:
        """Scan text using Hyperscan batch matching."""
        import hyperscan

        if self._db is None or not self._pattern_map:
            return []

        scratch = self._get_scratch()
        if scratch is None:
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
            """Callback for each Hyperscan match.

            Note: Without SOM_LEFTMOST, start is always 0 (scan offset).
            We estimate matched text by taking up to 100 chars before end.
            """
            if pattern_id < len(self._pattern_map):
                pattern, signature = self._pattern_map[pattern_id]
                # Estimate start since SOM_LEFTMOST is disabled
                estimated_start = max(0, end - 100)
                matched_text = text_bytes[estimated_start:end].decode("utf-8", errors="replace")
                context.append(
                    ScanMatch(
                        signature=signature,
                        matched_pattern=pattern,
                        matched_text=matched_text,
                        start=estimated_start,
                        end=end,
                    )
                )

        try:
            # Use thread-local scratch to avoid HS_SCRATCH_IN_USE errors
            self._db.scan(text_bytes, on_match, scratch=scratch, context=matches)
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
