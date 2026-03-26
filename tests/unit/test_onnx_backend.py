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

"""Unit tests for ONNX backend module."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest


def onnxruntime_available() -> bool:
    """Check if onnxruntime is available."""
    try:
        import onnxruntime  # noqa: F401
        return True
    except ImportError:
        return False


class TestONNXBackend:
    """Tests for ONNXBackend class."""

    def test_initial_state(self) -> None:
        """Test initial state of backend."""
        from aiproxyguard.scanner.ml.onnx_backend import ONNXBackend

        backend = ONNXBackend()
        assert backend.model_id == "unknown"
        assert backend.model_version == "0.0.0"
        assert backend.predict("test") == []

    def test_load_missing_file(self) -> None:
        """Test loading non-existent file raises appropriate error."""
        from aiproxyguard.scanner.ml.onnx_backend import ONNXBackend

        backend = ONNXBackend()

        # Depending on whether onnxruntime is installed, we get different errors
        with pytest.raises((ValueError, ImportError)):
            backend.load(Path("/nonexistent/model.onnx"))

    def test_load_without_onnxruntime(self) -> None:
        """Test that ImportError is raised without onnxruntime."""
        if onnxruntime_available():
            pytest.skip("onnxruntime is installed")

        from aiproxyguard.scanner.ml.onnx_backend import ONNXBackend

        backend = ONNXBackend()

        with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as f:
            f.write(b"dummy onnx content")
            path = f.name

        try:
            with pytest.raises(ImportError, match="onnxruntime is required"):
                backend.load(Path(path))
        finally:
            Path(path).unlink()

    def test_load_from_bytes_without_onnxruntime(self) -> None:
        """Test load_from_bytes without onnxruntime."""
        if onnxruntime_available():
            pytest.skip("onnxruntime is installed")

        from aiproxyguard.scanner.ml.onnx_backend import ONNXBackend

        backend = ONNXBackend()

        with pytest.raises(ImportError, match="onnxruntime is required"):
            backend.load_from_bytes(b"dummy", {"categories": ["safe"]})


@pytest.fixture
def mock_onnxruntime() -> Any:
    """Create mock onnxruntime module."""
    mock_ort = MagicMock()

    mock_session = MagicMock()
    mock_input = MagicMock()
    mock_input.name = "input_ids"
    mock_session.get_inputs.return_value = [mock_input]
    mock_ort.InferenceSession.return_value = mock_session
    mock_ort.SessionOptions.return_value = MagicMock()
    mock_ort.GraphOptimizationLevel.ORT_ENABLE_ALL = 99

    return mock_ort, mock_session


class TestONNXBackendWithMock:
    """Tests for ONNX backend with mocked onnxruntime."""

    def test_load_with_config(self, mock_onnxruntime: tuple) -> None:
        """Test loading with config file."""
        mock_ort, mock_session = mock_onnxruntime

        # Insert mock into sys.modules
        sys.modules["onnxruntime"] = mock_ort

        try:
            # Force reimport
            if "aiproxyguard.scanner.ml.onnx_backend" in sys.modules:
                del sys.modules["aiproxyguard.scanner.ml.onnx_backend"]

            from aiproxyguard.scanner.ml.onnx_backend import ONNXBackend

            with tempfile.TemporaryDirectory() as tmpdir:
                # Create model file
                model_path = Path(tmpdir) / "model.onnx"
                model_path.write_bytes(b"dummy onnx")

                # Create config file
                config_path = Path(tmpdir) / "config.json"
                config_path.write_text(json.dumps({
                    "categories": ["safe", "malicious"],
                    "model_id": "test-onnx-model",
                    "model_version": "2.0.0",
                }))

                backend = ONNXBackend()
                backend.load(Path(tmpdir))

                assert backend.model_id == "test-onnx-model"
                assert backend.model_version == "2.0.0"
                assert backend._categories == ["safe", "malicious"]
        finally:
            # Cleanup
            if "onnxruntime" in sys.modules:
                del sys.modules["onnxruntime"]

    def test_predict_with_probabilities(self, mock_onnxruntime: tuple) -> None:
        """Test prediction with direct probabilities."""
        import numpy as np

        mock_ort, mock_session = mock_onnxruntime

        # Mock session that returns probabilities
        mock_session.run.return_value = [np.array([[0.1, 0.8, 0.1]])]

        from aiproxyguard.scanner.ml.onnx_backend import ONNXBackend

        backend = ONNXBackend()
        backend._categories = ["safe", "prompt_injection", "jailbreak"]
        backend._session = mock_session

        results = backend.predict("test input")

        assert len(results) == 3
        assert results[0] == ("safe", 0.1)
        assert results[1] == ("prompt_injection", 0.8)
        assert results[2] == ("jailbreak", 0.1)

    def test_predict_with_softmax(self, mock_onnxruntime: tuple) -> None:
        """Test prediction with logits requiring softmax."""
        import numpy as np

        mock_ort, mock_session = mock_onnxruntime

        # Mock session that returns logits (values outside 0-1 range)
        mock_session.run.return_value = [np.array([[-1.0, 2.0, 0.5]])]

        from aiproxyguard.scanner.ml.onnx_backend import ONNXBackend

        backend = ONNXBackend()
        backend._categories = ["safe", "prompt_injection", "jailbreak"]
        backend._session = mock_session

        results = backend.predict("test input")

        assert len(results) == 3
        # Softmax should be applied, so values should sum to ~1
        total_prob = sum(r[1] for r in results)
        assert abs(total_prob - 1.0) < 0.01
