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

"""Unit tests for ML metrics module."""

from __future__ import annotations

from aiproxyguard.scanner.ml.metrics import (
    MLClassifierMetrics,
    get_ml_metrics,
    reset_ml_metrics,
)


class TestMLClassifierMetrics:
    """Tests for MLClassifierMetrics class."""

    def test_initial_state(self) -> None:
        """Test initial metrics state."""
        metrics = MLClassifierMetrics()

        assert metrics.predictions_total == 0
        assert metrics.predictions_blocked == 0
        assert metrics.errors_total == 0
        assert metrics.model_loaded is False

    def test_record_prediction(self) -> None:
        """Test recording predictions."""
        metrics = MLClassifierMetrics()

        metrics.record_prediction(
            category="prompt_injection",
            confidence=0.9,
            action="block",
            latency_ms=5.5,
        )

        assert metrics.predictions_total == 1
        assert metrics.predictions_blocked == 1
        assert metrics.predictions_by_category["prompt_injection"] == 1
        assert len(metrics.prediction_latencies_ms) == 1

    def test_record_multiple_predictions(self) -> None:
        """Test recording multiple predictions."""
        metrics = MLClassifierMetrics()

        metrics.record_prediction("prompt_injection", 0.9, "block", 5.0)
        metrics.record_prediction("jailbreak", 0.8, "block", 6.0)
        metrics.record_prediction("safe", 0.7, "allow", 4.0)

        assert metrics.predictions_total == 3
        assert metrics.predictions_blocked == 2
        assert metrics.predictions_allowed == 1
        assert metrics.predictions_by_category["prompt_injection"] == 1
        assert metrics.predictions_by_category["jailbreak"] == 1

    def test_record_error(self) -> None:
        """Test recording errors."""
        metrics = MLClassifierMetrics()

        metrics.record_error()
        metrics.record_error()

        assert metrics.errors_total == 2

    def test_record_model_load_success(self) -> None:
        """Test recording successful model load."""
        metrics = MLClassifierMetrics()

        metrics.record_model_load(
            success=True,
            model_id="test-model",
            version="1.0.0",
        )

        assert metrics.model_loads_total == 1
        assert metrics.model_load_failures == 0
        assert metrics.model_loaded is True
        assert metrics.model_id == "test-model"
        assert metrics.model_version == "1.0.0"

    def test_record_model_load_failure(self) -> None:
        """Test recording failed model load."""
        metrics = MLClassifierMetrics()

        metrics.record_model_load(success=False)

        assert metrics.model_loads_total == 1
        assert metrics.model_load_failures == 1
        assert metrics.model_loaded is False

    def test_record_license_refresh(self) -> None:
        """Test recording license refresh."""
        metrics = MLClassifierMetrics()

        metrics.record_license_refresh(success=True, expires_in_seconds=3600.0)

        assert metrics.license_refreshes == 1
        assert metrics.license_failures == 0
        assert metrics.license_expires_in_seconds == 3600.0

    def test_record_license_failure(self) -> None:
        """Test recording license failure."""
        metrics = MLClassifierMetrics()

        metrics.record_license_refresh(success=False)

        assert metrics.license_refreshes == 1
        assert metrics.license_failures == 1

    def test_latency_percentiles_empty(self) -> None:
        """Test percentiles with no data."""
        metrics = MLClassifierMetrics()

        percentiles = metrics.get_latency_percentiles()

        assert percentiles["p50"] == 0.0
        assert percentiles["p90"] == 0.0
        assert percentiles["p99"] == 0.0

    def test_latency_percentiles(self) -> None:
        """Test percentiles with data."""
        metrics = MLClassifierMetrics()

        # Add 100 latencies from 1 to 100
        for i in range(1, 101):
            metrics.prediction_latencies_ms.append(float(i))

        percentiles = metrics.get_latency_percentiles()

        assert percentiles["p50"] == 50.0
        assert percentiles["p90"] == 90.0
        assert percentiles["p99"] == 99.0

    def test_measure_prediction_context_manager(self) -> None:
        """Test measure_prediction context manager."""
        metrics = MLClassifierMetrics()

        with metrics.measure_prediction():
            # Simulate some work
            _ = sum(range(1000))

        assert len(metrics.prediction_latencies_ms) == 1
        assert metrics.prediction_latencies_ms[0] > 0

    def test_to_prometheus(self) -> None:
        """Test Prometheus format export."""
        metrics = MLClassifierMetrics()
        metrics.record_prediction("prompt_injection", 0.9, "block", 5.0)
        metrics.record_model_load(True, "test-model", "1.0.0")

        prometheus_output = metrics.to_prometheus()

        assert "ml_classifier_predictions_total 1" in prometheus_output
        assert 'category="prompt_injection"' in prometheus_output
        assert "ml_classifier_model_loaded 1" in prometheus_output
        assert 'model_id="test-model"' in prometheus_output

    def test_reset(self) -> None:
        """Test metrics reset."""
        metrics = MLClassifierMetrics()
        metrics.record_prediction("test", 0.5, "block", 5.0)
        metrics.record_error()
        metrics.record_model_load(True, "model", "1.0")

        metrics.reset()

        assert metrics.predictions_total == 0
        assert metrics.errors_total == 0
        assert metrics.model_loaded is False
        assert len(metrics.prediction_latencies_ms) == 0


class TestGlobalMetrics:
    """Tests for global metrics functions."""

    def test_get_ml_metrics(self) -> None:
        """Test getting global metrics instance."""
        reset_ml_metrics()

        metrics1 = get_ml_metrics()
        metrics2 = get_ml_metrics()

        assert metrics1 is metrics2

    def test_reset_ml_metrics(self) -> None:
        """Test resetting global metrics."""
        metrics = get_ml_metrics()
        metrics.record_prediction("test", 0.5, "block", 5.0)

        reset_ml_metrics()

        # Get again and verify reset
        metrics = get_ml_metrics()
        assert metrics.predictions_total == 0
