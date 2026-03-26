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

"""Scikit-learn backend for ML classifier."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SklearnBackend:
    """ML inference backend using scikit-learn models.

    Supports models saved with joblib or pickle that have:
    - A vectorizer (TfidfVectorizer or similar)
    - A classifier (LogisticRegression, SVM, etc.)
    - Category labels for multi-class classification
    """

    def __init__(self) -> None:
        """Initialize the sklearn backend."""
        self._model: Any = None
        self._vectorizer: Any = None
        self._categories: list[str] = []
        self._model_id: str = "unknown"
        self._model_version: str = "0.0.0"

    def load(self, model_path: Path) -> None:
        """Load model from joblib/pickle file.

        Expected model structure (dict or object with attributes):
        - vectorizer: sklearn text vectorizer
        - classifier: sklearn classifier with predict_proba
        - categories: list of category names
        - model_id: optional string identifier
        - model_version: optional version string

        Args:
            model_path: Path to the model file.

        Raises:
            ImportError: If joblib is not installed.
            ValueError: If model structure is invalid.
        """
        try:
            import joblib
        except ImportError as e:
            raise ImportError(
                "joblib is required for sklearn backend. "
                "Install with: pip install aiproxyguard[ml]"
            ) from e

        data = joblib.load(model_path)

        # Support both dict and object with attributes
        if isinstance(data, dict):
            self._vectorizer = data.get("vectorizer")
            self._model = data.get("classifier")
            self._categories = data.get("categories", [])
            self._model_id = data.get("model_id", "sklearn-classifier")
            self._model_version = data.get("model_version", "1.0.0")
        else:
            self._vectorizer = getattr(data, "vectorizer", None)
            self._model = getattr(data, "classifier", None)
            self._categories = getattr(data, "categories", [])
            self._model_id = getattr(data, "model_id", "sklearn-classifier")
            self._model_version = getattr(data, "model_version", "1.0.0")

        if self._vectorizer is None:
            raise ValueError("Model must contain a 'vectorizer'")
        if self._model is None:
            raise ValueError("Model must contain a 'classifier'")

        # Verify model has predict_proba
        if not hasattr(self._model, "predict_proba"):
            raise ValueError("Classifier must support predict_proba()")

        # Use classifier's actual classes - they're authoritative
        actual_classes = list(self._model.classes_)
        if self._categories and set(self._categories) != set(actual_classes):
            logger.warning(
                "Category mismatch: metadata says %s but model has %s. Using model classes.",
                self._categories,
                actual_classes,
            )
        self._categories = actual_classes

        if not self._categories:
            raise ValueError("Model must have at least one class")

        logger.debug(
            "Loaded sklearn model",
            extra={
                "model_id": self._model_id,
                "model_version": self._model_version,
                "categories": self._categories,
            },
        )

    def predict(self, text: str) -> list[tuple[str, float]]:
        """Predict categories with confidence scores.

        Args:
            text: Input text to classify.

        Returns:
            List of (category, confidence) tuples for all categories.
        """
        if self._model is None or self._vectorizer is None:
            return []

        # Vectorize the input text
        features = self._vectorizer.transform([text])

        # Get probability predictions
        probabilities = self._model.predict_proba(features)[0]

        # Use classifier's actual classes (more reliable than metadata)
        # This handles cases where training didn't include all categories
        classes = list(self._model.classes_)

        # Pair classes with their probabilities
        results = list(zip(classes, probabilities, strict=True))

        return results

    @property
    def model_id(self) -> str:
        """Get model identifier."""
        return self._model_id

    @property
    def model_version(self) -> str:
        """Get model version."""
        return self._model_version
