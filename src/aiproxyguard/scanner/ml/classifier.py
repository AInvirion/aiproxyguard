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

"""ML classifier for semantic prompt filtering."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from aiproxyguard.config import MLClassifierConfig

logger = logging.getLogger(__name__)


@dataclass
class MLMatch:
    """Result from ML classifier prediction."""

    category: str  # "prompt_injection", "jailbreak", etc.
    confidence: float  # 0.0 - 1.0
    model_id: str  # "prompt-classifier-v1"
    model_version: str  # "1.0.0"


class MLBackend(Protocol):
    """Protocol for ML inference backends."""

    def load(self, model_path: Path) -> None:
        """Load model from file."""
        ...

    def predict(self, text: str) -> list[tuple[str, float]]:
        """Predict categories with confidence scores.

        Returns list of (category, confidence) tuples.
        """
        ...

    @property
    def model_id(self) -> str:
        """Get model identifier."""
        ...

    @property
    def model_version(self) -> str:
        """Get model version."""
        ...


class MLClassifier:
    """ML-based classifier for prompt filtering.

    Integrates with the scanner pipeline to provide semantic
    classification of prompts using trained ML models.
    """

    def __init__(self, config: MLClassifierConfig) -> None:
        """Initialize the ML classifier.

        Args:
            config: ML classifier configuration.
        """
        self._config = config
        self._backend: MLBackend | None = None
        self._available = False

        if config.enabled:
            self._try_load_backend()

    def _try_load_backend(self) -> None:
        """Attempt to load the ML backend."""
        model_path = Path(self._config.model_path) if self._config.model_path else None

        if model_path is None or not model_path.exists():
            logger.warning(
                "ML classifier enabled but model not found",
                extra={"model_path": str(model_path)},
            )
            return

        # Determine backend based on file extension
        suffix = model_path.suffix.lower()

        try:
            if suffix in (".joblib", ".pkl", ".pickle"):
                from aiproxyguard.scanner.ml.sklearn_backend import SklearnBackend
                self._backend = SklearnBackend()
                self._backend.load(model_path)
                self._available = True
                logger.info(
                    "ML classifier loaded",
                    extra={
                        "model_id": self._backend.model_id,
                        "model_version": self._backend.model_version,
                        "backend": "sklearn",
                    },
                )
            elif suffix == ".onnx":
                from aiproxyguard.scanner.ml.onnx_backend import ONNXBackend
                self._backend = ONNXBackend()
                self._backend.load(model_path)
                self._available = True
                logger.info(
                    "ML classifier loaded",
                    extra={
                        "model_id": self._backend.model_id,
                        "model_version": self._backend.model_version,
                        "backend": "onnx",
                    },
                )
            else:
                logger.warning(f"Unknown model format: {suffix}")
        except ImportError as e:
            logger.warning(
                f"ML backend dependencies not installed: {e}. "
                "Install with: pip install aiproxyguard[ml]"
            )
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")

    def is_available(self) -> bool:
        """Check if the classifier is loaded and ready."""
        return self._available and self._backend is not None

    def predict(self, text: str) -> list[MLMatch]:
        """Classify text and return matches above threshold.

        Args:
            text: Input text to classify.

        Returns:
            List of MLMatch objects for predictions above threshold.
        """
        if not self.is_available():
            return []

        assert self._backend is not None

        try:
            predictions = self._backend.predict(text)
            matches = []

            for category, confidence in predictions:
                if confidence >= self._config.threshold:
                    matches.append(
                        MLMatch(
                            category=category,
                            confidence=confidence,
                            model_id=self._backend.model_id,
                            model_version=self._backend.model_version,
                        )
                    )

            return matches

        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return []

    def reload(self, model_path: Path | None = None) -> None:
        """Reload the model, optionally from a new path.

        Args:
            model_path: New model path, or None to reload current.
        """
        if model_path:
            self._config.model_path = str(model_path)

        self._available = False
        self._backend = None
        self._try_load_backend()

    def load_from_bytes(self, model_data: bytes, model_format: str | None = None) -> bool:
        """Load model from bytes (e.g., from control plane sync).

        SECURITY WARNING: This method uses joblib/pickle to deserialize bytes
        for sklearn models. Only call with data that has been cryptographically
        verified (e.g., decrypted from an encrypted model with license validation).
        Never call with unverified network data - this enables code execution.

        Args:
            model_data: Raw model bytes. MUST be from a trusted source.
            model_format: Optional format hint ("sklearn", "onnx"). Auto-detected if None.

        Returns:
            True if loading was successful.
        """
        # Auto-detect format based on magic bytes if not specified
        if model_format is None:
            # ONNX files start with "ONNX" magic (0x4F 0x4E 0x4E 0x58 after protobuf header)
            # or contain the ONNX protobuf tag early in the file
            if len(model_data) > 8:
                # Check for ONNX protobuf structure (starts with 0x08 for field 1 varint)
                # and contains "onnx" or "ir_version" markers
                header = model_data[:100]
                if b"onnx" in header.lower() or b"ir_version" in header:
                    model_format = "onnx"
                # Also check for protobuf ONNX structure
                elif model_data[0:1] == b"\x08" and len(model_data) > 50000:
                    # Large protobuf file - likely ONNX
                    model_format = "onnx"
                else:
                    model_format = "sklearn"
            else:
                model_format = "sklearn"

        if model_format == "onnx":
            return self._load_onnx_from_bytes(model_data)
        else:
            return self._load_sklearn_from_bytes(model_data)

    def _load_onnx_from_bytes(self, model_data: bytes) -> bool:
        """Load ONNX model from bytes."""
        try:
            from aiproxyguard.scanner.ml.onnx_backend import ONNXBackend

            backend = ONNXBackend()
            backend.load_from_bytes(model_data)

            self._backend = backend
            self._available = True

            logger.info(
                "ML classifier loaded from bytes (ONNX)",
                extra={
                    "model_id": backend.model_id,
                    "model_version": backend.model_version,
                    "backend": "onnx",
                },
            )
            return True

        except ImportError as e:
            logger.warning(
                f"ONNX backend dependencies not installed: {e}. "
                "Install with: pip install aiproxyguard[enterprise]"
            )
            return False
        except Exception as e:
            logger.error(f"Failed to load ONNX model from bytes: {e}")
            self._available = False
            self._backend = None
            return False

    def _load_sklearn_from_bytes(self, model_data: bytes) -> bool:
        """Load sklearn model from bytes."""
        import tempfile

        try:
            import joblib  # noqa: F401 - needed for tempfile suffix check
        except ImportError:
            logger.warning("joblib not installed, cannot load sklearn model from bytes")
            return False

        try:
            from aiproxyguard.scanner.ml.sklearn_backend import SklearnBackend

            # Write to temp file and use SklearnBackend.load() for proper validation
            # This ensures we run the same integrity checks as file-based loading
            with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
                f.write(model_data)
                temp_path = f.name

            try:
                backend = SklearnBackend()
                backend.load(Path(temp_path))

                self._backend = backend
                self._available = True

                logger.info(
                    "ML classifier loaded from bytes (sklearn)",
                    extra={
                        "model_id": backend.model_id,
                        "model_version": backend.model_version,
                        "backend": "sklearn",
                    },
                )
                return True
            finally:
                # Clean up temp file
                import os
                os.unlink(temp_path)

        except Exception as e:
            logger.error(f"Failed to load sklearn model from bytes: {e}")
            self._available = False
            self._backend = None
            return False

    @property
    def model_info(self) -> dict | None:
        """Get information about the loaded model."""
        if not self.is_available() or self._backend is None:
            return None

        return {
            "model_id": self._backend.model_id,
            "model_version": self._backend.model_version,
            "threshold": self._config.threshold,
            "action": self._config.action,
        }

    def health_check(self) -> dict:
        """Perform health check on the ML classifier.

        Returns:
            Dict with health status and details.
        """
        status = {
            "healthy": False,
            "enabled": self._config.enabled,
            "available": self._available,
            "model_id": None,
            "model_version": None,
            "backend": None,
            "error": None,
        }

        if not self._config.enabled:
            status["healthy"] = True  # Disabled is a valid healthy state
            status["error"] = "ML classifier disabled"
            return status

        if not self._available or self._backend is None:
            status["error"] = "Model not loaded"
            return status

        try:
            # Try a simple prediction to verify the model works
            test_result = self._backend.predict("test health check")
            if test_result is not None:
                status["healthy"] = True
                status["model_id"] = self._backend.model_id
                status["model_version"] = self._backend.model_version
                status["backend"] = type(self._backend).__name__
            else:
                status["error"] = "Prediction returned None"
        except Exception as e:
            status["error"] = str(e)

        return status
