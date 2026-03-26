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

"""Metrics collection for ML classifier.

Provides Prometheus-compatible metrics for monitoring ML classifier
performance in production.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Generator

logger = logging.getLogger(__name__)


def _escape_prometheus_label(value: str) -> str:
    """Escape a string for use as a Prometheus label value.

    Per Prometheus text exposition format:
    - Backslash -> \\
    - Double quote -> \"
    - Newline -> \n
    """
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


@dataclass
class MLClassifierMetrics:
    """Metrics collector for ML classifier operations."""

    # Counters
    predictions_total: int = 0
    predictions_by_category: dict[str, int] = field(default_factory=dict)
    predictions_blocked: int = 0
    predictions_allowed: int = 0
    errors_total: int = 0
    model_loads_total: int = 0
    model_load_failures: int = 0
    license_refreshes: int = 0
    license_failures: int = 0

    # Gauges
    model_loaded: bool = False
    model_id: str = ""
    model_version: str = ""
    license_expires_in_seconds: float = 0.0

    # Histograms (simplified as lists for now)
    prediction_latencies_ms: list[float] = field(default_factory=list)
    _max_latencies: int = 1000  # Keep last N latencies

    def record_prediction(
        self,
        category: str,
        confidence: float,
        action: str,
        latency_ms: float,
    ) -> None:
        """Record a prediction result."""
        self.predictions_total += 1

        # Track by category
        if category not in self.predictions_by_category:
            self.predictions_by_category[category] = 0
        self.predictions_by_category[category] += 1

        # Track by action
        if action == "block":
            self.predictions_blocked += 1
        else:
            self.predictions_allowed += 1

        # Record latency
        self.prediction_latencies_ms.append(latency_ms)
        if len(self.prediction_latencies_ms) > self._max_latencies:
            self.prediction_latencies_ms = self.prediction_latencies_ms[-self._max_latencies:]

    def record_error(self) -> None:
        """Record a prediction error."""
        self.errors_total += 1

    def record_model_load(self, success: bool, model_id: str = "", version: str = "") -> None:
        """Record a model load attempt."""
        self.model_loads_total += 1
        if success:
            self.model_loaded = True
            self.model_id = model_id
            self.model_version = version
        else:
            self.model_load_failures += 1
            self.model_loaded = False

    def record_license_refresh(self, success: bool, expires_in_seconds: float = 0.0) -> None:
        """Record a license refresh attempt."""
        self.license_refreshes += 1
        if success:
            self.license_expires_in_seconds = expires_in_seconds
        else:
            self.license_failures += 1

    @contextmanager
    def measure_prediction(self) -> Generator[None, None, None]:
        """Context manager to measure prediction latency."""
        start = time.perf_counter()
        try:
            yield
        finally:
            latency_ms = (time.perf_counter() - start) * 1000
            self.prediction_latencies_ms.append(latency_ms)
            if len(self.prediction_latencies_ms) > self._max_latencies:
                self.prediction_latencies_ms = self.prediction_latencies_ms[-self._max_latencies:]

    def get_latency_percentiles(self) -> dict[str, float]:
        """Get latency percentiles (p50, p90, p99)."""
        if not self.prediction_latencies_ms:
            return {"p50": 0.0, "p90": 0.0, "p99": 0.0}

        sorted_latencies = sorted(self.prediction_latencies_ms)
        n = len(sorted_latencies)

        # Use (n-1) for correct 0-based indexing (nearest rank method)
        return {
            "p50": sorted_latencies[int((n - 1) * 0.50)],
            "p90": sorted_latencies[int((n - 1) * 0.90)] if n >= 10 else sorted_latencies[-1],
            "p99": sorted_latencies[int((n - 1) * 0.99)] if n >= 100 else sorted_latencies[-1],
        }

    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []

        # Counters
        lines.append("# HELP ml_classifier_predictions_total Total predictions made")
        lines.append("# TYPE ml_classifier_predictions_total counter")
        lines.append(f"ml_classifier_predictions_total {self.predictions_total}")

        lines.append("# HELP ml_classifier_predictions_by_category Predictions by category")
        lines.append("# TYPE ml_classifier_predictions_by_category counter")
        for category, count in self.predictions_by_category.items():
            escaped_cat = _escape_prometheus_label(category)
            lines.append(f'ml_classifier_predictions_by_category{{category="{escaped_cat}"}} {count}')

        lines.append("# HELP ml_classifier_predictions_blocked Predictions resulting in block")
        lines.append("# TYPE ml_classifier_predictions_blocked counter")
        lines.append(f"ml_classifier_predictions_blocked {self.predictions_blocked}")

        lines.append("# HELP ml_classifier_predictions_allowed Predictions resulting in allow")
        lines.append("# TYPE ml_classifier_predictions_allowed counter")
        lines.append(f"ml_classifier_predictions_allowed {self.predictions_allowed}")

        lines.append("# HELP ml_classifier_errors_total Total prediction errors")
        lines.append("# TYPE ml_classifier_errors_total counter")
        lines.append(f"ml_classifier_errors_total {self.errors_total}")

        lines.append("# HELP ml_classifier_model_loads_total Total model load attempts")
        lines.append("# TYPE ml_classifier_model_loads_total counter")
        lines.append(f"ml_classifier_model_loads_total {self.model_loads_total}")

        lines.append("# HELP ml_classifier_model_load_failures_total Failed model loads")
        lines.append("# TYPE ml_classifier_model_load_failures_total counter")
        lines.append(f"ml_classifier_model_load_failures_total {self.model_load_failures}")

        # Gauges
        lines.append("# HELP ml_classifier_model_loaded Whether a model is currently loaded")
        lines.append("# TYPE ml_classifier_model_loaded gauge")
        lines.append(f"ml_classifier_model_loaded {1 if self.model_loaded else 0}")

        lines.append("# HELP ml_classifier_license_expires_seconds Seconds until license expires")
        lines.append("# TYPE ml_classifier_license_expires_seconds gauge")
        lines.append(f"ml_classifier_license_expires_seconds {self.license_expires_in_seconds:.0f}")

        # Info
        if self.model_id:
            escaped_id = _escape_prometheus_label(self.model_id)
            escaped_version = _escape_prometheus_label(self.model_version)
            lines.append("# HELP ml_classifier_model_info Model information")
            lines.append("# TYPE ml_classifier_model_info gauge")
            lines.append(
                f'ml_classifier_model_info{{model_id="{escaped_id}",'
                f'version="{escaped_version}"}} 1'
            )

        # Histograms (simplified as summary)
        percentiles = self.get_latency_percentiles()
        lines.append("# HELP ml_classifier_prediction_latency_ms Prediction latency in milliseconds")
        lines.append("# TYPE ml_classifier_prediction_latency_ms summary")
        lines.append(f'ml_classifier_prediction_latency_ms{{quantile="0.5"}} {percentiles["p50"]:.2f}')
        lines.append(f'ml_classifier_prediction_latency_ms{{quantile="0.9"}} {percentiles["p90"]:.2f}')
        lines.append(f'ml_classifier_prediction_latency_ms{{quantile="0.99"}} {percentiles["p99"]:.2f}')

        return "\n".join(lines)

    def reset(self) -> None:
        """Reset all metrics (useful for testing)."""
        self.predictions_total = 0
        self.predictions_by_category.clear()
        self.predictions_blocked = 0
        self.predictions_allowed = 0
        self.errors_total = 0
        self.model_loads_total = 0
        self.model_load_failures = 0
        self.license_refreshes = 0
        self.license_failures = 0
        self.model_loaded = False
        self.model_id = ""
        self.model_version = ""
        self.license_expires_in_seconds = 0.0
        self.prediction_latencies_ms.clear()


# Global metrics instance
_metrics: MLClassifierMetrics | None = None


def get_ml_metrics() -> MLClassifierMetrics:
    """Get the global ML classifier metrics instance."""
    global _metrics
    if _metrics is None:
        _metrics = MLClassifierMetrics()
    return _metrics


def reset_ml_metrics() -> None:
    """Reset the global ML classifier metrics."""
    global _metrics
    if _metrics:
        _metrics.reset()
