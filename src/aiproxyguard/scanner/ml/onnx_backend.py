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

"""ONNX backend for ML classifier (Enterprise tier).

Supports transformer-based models exported to ONNX format for
high-performance inference without Python ML dependencies.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ONNXBackend:
    """ML inference backend using ONNX Runtime.

    Supports models exported from:
    - Hugging Face transformers (DistilBERT, RoBERTa, etc.)
    - scikit-learn (via skl2onnx)
    - PyTorch (via torch.onnx)

    Model package should include:
    - model.onnx: The ONNX model file
    - config.json: Model configuration with categories, tokenizer info
    - tokenizer/ (optional): Tokenizer files for transformer models
    """

    def __init__(self) -> None:
        """Initialize the ONNX backend."""
        self._session: Any = None
        self._tokenizer: Any = None
        self._categories: list[str] = []
        self._model_id: str = "unknown"
        self._model_version: str = "0.0.0"
        self._input_name: str = "input"
        self._max_length: int = 512

    def load(self, model_path: Path) -> None:
        """Load ONNX model from file or directory.

        Args:
            model_path: Path to .onnx file or directory containing model.onnx

        Raises:
            ImportError: If onnxruntime is not installed.
            ValueError: If model structure is invalid.
        """
        try:
            import onnxruntime as ort
        except ImportError as e:
            raise ImportError(
                "onnxruntime is required for ONNX backend. "
                "Install with: pip install aiproxyguard[enterprise]"
            ) from e

        # Determine model file and config paths
        if model_path.is_dir():
            onnx_file = model_path / "model.onnx"
            config_file = model_path / "config.json"
            tokenizer_dir = model_path / "tokenizer"
        else:
            onnx_file = model_path
            config_file = model_path.with_suffix(".json")
            tokenizer_dir = model_path.parent / "tokenizer"

        if not onnx_file.exists():
            raise ValueError(f"ONNX model not found: {onnx_file}")

        # Load configuration
        if config_file.exists():
            with open(config_file) as f:
                config = json.load(f)
            self._categories = config.get("categories", [])
            self._model_id = config.get("model_id", "onnx-classifier")
            self._model_version = config.get("model_version", "1.0.0")
            self._input_name = config.get("input_name", "input_ids")
            self._max_length = config.get("max_length", 512)
        else:
            logger.warning(f"Config file not found: {config_file}, using defaults")
            self._categories = ["safe", "prompt-injection", "jailbreak"]

        # Load ONNX session with optimizations
        sess_options = ort.SessionOptions()
        sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        sess_options.intra_op_num_threads = 2
        sess_options.inter_op_num_threads = 2

        # Use CPU execution provider (GPU support can be added later)
        providers = ["CPUExecutionProvider"]

        self._session = ort.InferenceSession(
            str(onnx_file),
            sess_options=sess_options,
            providers=providers,
        )

        # Get input name from model if not in config
        input_info = self._session.get_inputs()
        if input_info:
            self._input_name = input_info[0].name

        # Try to load tokenizer for transformer models
        self._load_tokenizer(tokenizer_dir)

        logger.debug(
            "Loaded ONNX model",
            extra={
                "model_id": self._model_id,
                "model_version": self._model_version,
                "categories": self._categories,
                "input_name": self._input_name,
            },
        )

    def _load_tokenizer(self, tokenizer_dir: Path) -> None:
        """Try to load a tokenizer for transformer models."""
        if not tokenizer_dir.exists():
            return

        try:
            from transformers import AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(str(tokenizer_dir))
            logger.debug(f"Loaded tokenizer from {tokenizer_dir}")
        except ImportError:
            logger.debug("transformers not installed, using simple tokenization")
        except Exception as e:
            logger.warning(f"Failed to load tokenizer: {e}")

    def _simple_tokenize(self, text: str) -> dict[str, Any]:
        """Simple tokenization for sklearn-exported ONNX models."""
        import numpy as np

        # For sklearn models, just pass text as string input
        # The model should have a string vectorizer built in
        # Use 1D array [text] - sklearn ONNX export expects this shape
        return {self._input_name: np.array([text], dtype=object)}

    def _transformer_tokenize(self, text: str) -> dict[str, Any]:
        """Tokenize text using HuggingFace tokenizer."""
        import numpy as np

        tokens = self._tokenizer(
            text,
            max_length=self._max_length,
            padding="max_length",
            truncation=True,
            return_tensors="np",
        )

        return {
            "input_ids": tokens["input_ids"].astype(np.int64),
            "attention_mask": tokens["attention_mask"].astype(np.int64),
        }

    def predict(self, text: str) -> list[tuple[str, float]]:
        """Predict categories with confidence scores.

        Args:
            text: Input text to classify.

        Returns:
            List of (category, confidence) tuples for all categories.
        """
        if self._session is None:
            return []

        try:
            import numpy as np

            # Tokenize based on available tokenizer
            if self._tokenizer is not None:
                inputs = self._transformer_tokenize(text)
            else:
                inputs = self._simple_tokenize(text)

            # Run inference
            outputs = self._session.run(None, inputs)

            # Handle sklearn ONNX output format: [label, [{class: prob}]]
            # vs transformer format: [logits_array]
            if len(outputs) >= 2 and isinstance(outputs[1], list):
                # sklearn ONNX format: output_probability is list of dicts
                prob_dict = outputs[1][0]  # First (only) sample's probabilities
                return [(cat, prob_dict.get(cat, 0.0)) for cat in self._categories]

            # Transformer format: output is logits/probabilities array
            logits = outputs[0]

            # Apply softmax if needed (check if values look like logits)
            if isinstance(logits, np.ndarray):
                if logits.min() < 0 or logits.max() > 1:
                    # Apply softmax
                    exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
                    probabilities = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)
                else:
                    probabilities = logits

                # Flatten if needed
                if probabilities.ndim > 1:
                    probabilities = probabilities[0]

                # Pair with categories
                if len(probabilities) != len(self._categories):
                    logger.warning(
                        f"Output size mismatch: {len(probabilities)} vs {len(self._categories)} categories"
                    )
                    min_len = min(len(probabilities), len(self._categories))
                    return list(zip(self._categories[:min_len], probabilities[:min_len].tolist()))

                return list(zip(self._categories, probabilities.tolist()))

            logger.warning(f"Unexpected output format: {type(outputs[0])}")
            return []

        except Exception as e:
            logger.error(f"ONNX prediction failed: {e}")
            return []

    def load_from_bytes(self, model_bytes: bytes, config: dict | None = None) -> None:
        """Load ONNX model from bytes.

        Args:
            model_bytes: Raw ONNX model bytes
            config: Optional configuration dict
        """
        try:
            import onnxruntime as ort
        except ImportError as e:
            raise ImportError(
                "onnxruntime is required for ONNX backend. "
                "Install with: pip install aiproxyguard[enterprise]"
            ) from e

        # Apply config
        if config:
            self._categories = config.get("categories", self._categories)
            self._model_id = config.get("model_id", self._model_id)
            self._model_version = config.get("model_version", self._model_version)
            self._input_name = config.get("input_name", self._input_name)
            self._max_length = config.get("max_length", self._max_length)

        # Load session from bytes
        sess_options = ort.SessionOptions()
        sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

        self._session = ort.InferenceSession(
            model_bytes,
            sess_options=sess_options,
            providers=["CPUExecutionProvider"],
        )

        # Get input name from model
        input_info = self._session.get_inputs()
        if input_info:
            self._input_name = input_info[0].name

        logger.info(
            "ONNX model loaded from bytes",
            extra={
                "model_id": self._model_id,
                "model_version": self._model_version,
            },
        )

    @property
    def model_id(self) -> str:
        """Get model identifier."""
        return self._model_id

    @property
    def model_version(self) -> str:
        """Get model version."""
        return self._model_version
