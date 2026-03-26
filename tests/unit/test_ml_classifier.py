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

"""Unit tests for ML classifier module."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from aiproxyguard.config import MLClassifierConfig
from aiproxyguard.scanner.ml import MLClassifier, MLMatch


class TestMLMatch:
    """Tests for MLMatch dataclass."""

    def test_create_match(self) -> None:
        """Test creating an MLMatch instance."""
        match = MLMatch(
            category="prompt_injection",
            confidence=0.95,
            model_id="test-model",
            model_version="1.0.0",
        )
        assert match.category == "prompt_injection"
        assert match.confidence == 0.95
        assert match.model_id == "test-model"
        assert match.model_version == "1.0.0"


@pytest.fixture
def mock_sklearn_backend() -> MagicMock:
    """Create a mock sklearn backend."""
    backend = MagicMock()
    backend.model_id = "test-model"
    backend.model_version = "1.0.0"
    backend.predict.return_value = []
    return backend


@pytest.fixture
def mock_joblib() -> MagicMock:
    """Create a mock joblib module."""
    return MagicMock()


class TestMLClassifier:
    """Tests for MLClassifier class."""

    def test_disabled_classifier(self) -> None:
        """Test classifier when disabled."""
        config = MLClassifierConfig(enabled=False)
        classifier = MLClassifier(config)
        assert not classifier.is_available()
        assert classifier.predict("test input") == []
        assert classifier.model_info is None

    def test_enabled_but_no_model_path(self) -> None:
        """Test classifier enabled but no model path."""
        config = MLClassifierConfig(enabled=True, model_path=None)
        classifier = MLClassifier(config)
        assert not classifier.is_available()
        assert classifier.predict("test input") == []

    def test_enabled_but_model_not_found(self) -> None:
        """Test classifier enabled but model file doesn't exist."""
        config = MLClassifierConfig(
            enabled=True, model_path="/nonexistent/model.joblib"
        )
        classifier = MLClassifier(config)
        assert not classifier.is_available()
        assert classifier.predict("test input") == []

    def test_unknown_model_format(self) -> None:
        """Test classifier with unknown model format."""
        with tempfile.NamedTemporaryFile(suffix=".unknown", delete=False) as f:
            f.write(b"dummy")
            path = f.name

        try:
            config = MLClassifierConfig(enabled=True, model_path=path)
            classifier = MLClassifier(config)
            assert not classifier.is_available()
        finally:
            Path(path).unlink()

    def test_sklearn_backend_load(self, mock_sklearn_backend: MagicMock) -> None:
        """Test loading sklearn backend."""
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            f.write(b"dummy")
            path = f.name

        try:
            with patch(
                "aiproxyguard.scanner.ml.sklearn_backend.SklearnBackend",
                return_value=mock_sklearn_backend,
            ):
                config = MLClassifierConfig(enabled=True, model_path=path)
                classifier = MLClassifier(config)

                assert classifier.is_available()
                mock_sklearn_backend.load.assert_called_once()
        finally:
            Path(path).unlink()

    def test_predict_filters_by_threshold(
        self, mock_sklearn_backend: MagicMock
    ) -> None:
        """Test that predictions below threshold are filtered out."""
        mock_sklearn_backend.predict.return_value = [
            ("prompt_injection", 0.9),
            ("jailbreak", 0.5),
            ("safe", 0.1),
        ]

        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            f.write(b"dummy")
            path = f.name

        try:
            with patch(
                "aiproxyguard.scanner.ml.sklearn_backend.SklearnBackend",
                return_value=mock_sklearn_backend,
            ):
                config = MLClassifierConfig(
                    enabled=True, model_path=path, threshold=0.7
                )
                classifier = MLClassifier(config)

                matches = classifier.predict("test input")

                assert len(matches) == 1
                assert matches[0].category == "prompt_injection"
                assert matches[0].confidence == 0.9
        finally:
            Path(path).unlink()

    def test_predict_multiple_matches(self, mock_sklearn_backend: MagicMock) -> None:
        """Test predictions with multiple matches above threshold."""
        mock_sklearn_backend.predict.return_value = [
            ("prompt_injection", 0.85),
            ("jailbreak", 0.80),
        ]

        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            f.write(b"dummy")
            path = f.name

        try:
            with patch(
                "aiproxyguard.scanner.ml.sklearn_backend.SklearnBackend",
                return_value=mock_sklearn_backend,
            ):
                config = MLClassifierConfig(
                    enabled=True, model_path=path, threshold=0.7
                )
                classifier = MLClassifier(config)

                matches = classifier.predict("test input")

                assert len(matches) == 2
                categories = {m.category for m in matches}
                assert categories == {"prompt_injection", "jailbreak"}
        finally:
            Path(path).unlink()

    def test_model_info(self, mock_sklearn_backend: MagicMock) -> None:
        """Test model_info property."""
        mock_sklearn_backend.model_id = "prompt-classifier-v1"
        mock_sklearn_backend.model_version = "2.0.0"

        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            f.write(b"dummy")
            path = f.name

        try:
            with patch(
                "aiproxyguard.scanner.ml.sklearn_backend.SklearnBackend",
                return_value=mock_sklearn_backend,
            ):
                config = MLClassifierConfig(
                    enabled=True, model_path=path, threshold=0.8, action="warn"
                )
                classifier = MLClassifier(config)

                info = classifier.model_info
                assert info is not None
                assert info["model_id"] == "prompt-classifier-v1"
                assert info["model_version"] == "2.0.0"
                assert info["threshold"] == 0.8
                assert info["action"] == "warn"
        finally:
            Path(path).unlink()

    def test_reload_model(self, mock_sklearn_backend: MagicMock) -> None:
        """Test reloading the model."""
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            f.write(b"dummy")
            path = f.name

        try:
            with patch(
                "aiproxyguard.scanner.ml.sklearn_backend.SklearnBackend",
                return_value=mock_sklearn_backend,
            ):
                config = MLClassifierConfig(enabled=True, model_path=path)
                classifier = MLClassifier(config)

                assert classifier.is_available()
                assert mock_sklearn_backend.load.call_count == 1

                # Reload
                classifier.reload()
                assert mock_sklearn_backend.load.call_count == 2
        finally:
            Path(path).unlink()

    def test_reload_with_new_path(self, mock_sklearn_backend: MagicMock) -> None:
        """Test reloading with a new model path."""
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f1:
            f1.write(b"dummy1")
            path1 = f1.name

        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f2:
            f2.write(b"dummy2")
            path2 = f2.name

        try:
            with patch(
                "aiproxyguard.scanner.ml.sklearn_backend.SklearnBackend",
                return_value=mock_sklearn_backend,
            ):
                config = MLClassifierConfig(enabled=True, model_path=path1)
                classifier = MLClassifier(config)

                # Reload with new path
                classifier.reload(Path(path2))
                assert classifier._config.model_path == path2
        finally:
            Path(path1).unlink()
            Path(path2).unlink()

    def test_predict_handles_exception(self, mock_sklearn_backend: MagicMock) -> None:
        """Test that prediction errors are handled gracefully."""
        mock_sklearn_backend.predict.side_effect = RuntimeError("Model error")

        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            f.write(b"dummy")
            path = f.name

        try:
            with patch(
                "aiproxyguard.scanner.ml.sklearn_backend.SklearnBackend",
                return_value=mock_sklearn_backend,
            ):
                config = MLClassifierConfig(enabled=True, model_path=path)
                classifier = MLClassifier(config)

                # Should not raise, return empty list
                matches = classifier.predict("test input")
                assert matches == []
        finally:
            Path(path).unlink()

    def test_onnx_backend_not_implemented(self) -> None:
        """Test that ONNX backend shows warning."""
        with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as f:
            f.write(b"dummy")
            path = f.name

        try:
            config = MLClassifierConfig(enabled=True, model_path=path)
            classifier = MLClassifier(config)
            # ONNX not yet implemented, should not be available
            assert not classifier.is_available()
        finally:
            Path(path).unlink()

    def test_pickle_format_supported(self, mock_sklearn_backend: MagicMock) -> None:
        """Test that .pkl and .pickle formats are recognized."""
        for suffix in [".pkl", ".pickle"]:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
                f.write(b"dummy")
                path = f.name

            try:
                with patch(
                    "aiproxyguard.scanner.ml.sklearn_backend.SklearnBackend",
                    return_value=mock_sklearn_backend,
                ):
                    config = MLClassifierConfig(enabled=True, model_path=path)
                    classifier = MLClassifier(config)
                    assert classifier.is_available()
            finally:
                Path(path).unlink()


class TestLoadFromBytes:
    """Tests for load_from_bytes method."""

    def test_load_from_bytes_success(self) -> None:
        """Test loading model from bytes."""
        try:
            import joblib
            import numpy as np
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
        except ImportError:
            pytest.skip("sklearn not installed")

        # Create a simple model
        vectorizer = TfidfVectorizer(max_features=100)
        X = vectorizer.fit_transform(["test prompt", "another test"])
        classifier = LogisticRegression()
        classifier.fit(X, [0, 1])

        model_data = {
            "vectorizer": vectorizer,
            "classifier": classifier,
            "categories": ["safe", "prompt_injection"],
            "model_id": "test-bytes-model",
            "model_version": "1.0.0",
        }

        # Serialize to bytes
        import io
        buffer = io.BytesIO()
        joblib.dump(model_data, buffer)
        model_bytes = buffer.getvalue()

        # Load from bytes
        config = MLClassifierConfig(enabled=True)
        classifier = MLClassifier(config)
        assert not classifier.is_available()

        result = classifier.load_from_bytes(model_bytes)
        assert result is True
        assert classifier.is_available()
        assert classifier.model_info is not None
        assert classifier.model_info["model_id"] == "test-bytes-model"

    def test_load_from_bytes_invalid_data(self) -> None:
        """Test that invalid bytes fail gracefully."""
        config = MLClassifierConfig(enabled=True)
        classifier = MLClassifier(config)

        result = classifier.load_from_bytes(b"not valid joblib data")
        assert result is False
        assert not classifier.is_available()
