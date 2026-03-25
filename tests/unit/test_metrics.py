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

"""Tests for Prometheus metrics."""

from aiproxyguard.metrics import MetricsCollector


class TestMetricsCollector:
    """Test metrics collection."""

    def test_record_request(self) -> None:
        """Record request metrics."""
        collector = MetricsCollector()

        collector.record_request(upstream="openai", method="POST", status=200, duration=0.5)

        # Verify counter incremented
        assert collector.get_request_count("openai", "POST", 200) == 1

    def test_record_scan(self) -> None:
        """Record scan metrics."""
        collector = MetricsCollector()

        collector.record_scan(scanner="regex", result="block", duration=0.01)

        assert collector.get_scan_count("regex", "block") == 1

    def test_record_detection(self) -> None:
        """Record detection metrics."""
        collector = MetricsCollector()

        collector.record_detection(category="prompt_injection", action="block", signature_id="PI-001")

        assert collector.get_detection_count("prompt_injection", "block") == 1

    def test_record_detection_without_signature(self) -> None:
        """Record detection without signature_id."""
        collector = MetricsCollector()

        collector.record_detection(category="heuristic_match", action="warn")

        assert collector.get_detection_count("heuristic_match", "warn") == 1

    def test_set_signatures_loaded(self) -> None:
        """Set loaded signature count."""
        collector = MetricsCollector()

        # Should not raise
        collector.set_signatures_loaded(tier="free", count=10)

    def test_cumulative_counts(self) -> None:
        """Multiple records accumulate correctly."""
        collector = MetricsCollector()

        collector.record_request(upstream="openai", method="POST", status=200, duration=0.1)
        collector.record_request(upstream="openai", method="POST", status=200, duration=0.2)

        assert collector.get_request_count("openai", "POST", 200) == 2
