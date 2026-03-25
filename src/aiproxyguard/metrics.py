"""Prometheus metrics collection."""

from __future__ import annotations

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST


# Request metrics
REQUESTS_TOTAL = Counter(
    "aiproxyguard_requests_total",
    "Total requests processed",
    ["upstream", "method", "status"],
)

REQUEST_DURATION = Histogram(
    "aiproxyguard_request_duration_seconds",
    "Request duration in seconds",
    ["upstream"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# Scanner metrics
SCANS_TOTAL = Counter(
    "aiproxyguard_scans_total",
    "Total scans performed",
    ["scanner", "result"],
)

SCAN_DURATION = Histogram(
    "aiproxyguard_scan_duration_seconds",
    "Scan duration in seconds",
    ["scanner"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1],
)

# Detection metrics
DETECTIONS_TOTAL = Counter(
    "aiproxyguard_detections_total",
    "Total detections",
    ["category", "action"],
)

# Signature metrics
SIGNATURES_LOADED = Gauge(
    "aiproxyguard_signatures_loaded",
    "Number of signatures loaded",
    ["tier"],
)

SIGNATURE_SYNC_TIMESTAMP = Gauge(
    "aiproxyguard_signature_sync_timestamp_seconds",
    "Last successful signature sync timestamp in seconds since epoch",
)


class MetricsCollector:
    """Collect and expose Prometheus metrics."""

    def __init__(self) -> None:
        """Initialize collector."""
        # Track counts locally for testing
        self._request_counts: dict[tuple[str, str, int], int] = {}
        self._scan_counts: dict[tuple[str, str], int] = {}
        self._detection_counts: dict[tuple[str, str], int] = {}

    def record_request(
        self,
        upstream: str,
        method: str,
        status: int,
        duration: float,
    ) -> None:
        """Record request metrics."""
        REQUESTS_TOTAL.labels(upstream=upstream, method=method, status=status).inc()
        REQUEST_DURATION.labels(upstream=upstream).observe(duration)

        key = (upstream, method, status)
        self._request_counts[key] = self._request_counts.get(key, 0) + 1

    def record_scan(
        self,
        scanner: str,
        result: str,
        duration: float,
    ) -> None:
        """Record scan metrics."""
        SCANS_TOTAL.labels(scanner=scanner, result=result).inc()
        SCAN_DURATION.labels(scanner=scanner).observe(duration)

        key = (scanner, result)
        self._scan_counts[key] = self._scan_counts.get(key, 0) + 1

    def record_detection(
        self,
        category: str,
        action: str,
        signature_id: str | None = None,
    ) -> None:
        """Record detection metrics."""
        DETECTIONS_TOTAL.labels(category=category, action=action).inc()
        # signature_id is intentionally not a label due to cardinality concerns
        # It can be logged separately if needed

        key = (category, action)
        self._detection_counts[key] = self._detection_counts.get(key, 0) + 1

    def set_signatures_loaded(self, tier: str, count: int) -> None:
        """Set number of loaded signatures."""
        SIGNATURES_LOADED.labels(tier=tier).set(count)

    def set_signature_sync_timestamp(self, timestamp: float) -> None:
        """Set last sync timestamp."""
        SIGNATURE_SYNC_TIMESTAMP.set(timestamp)

    def get_request_count(self, upstream: str, method: str, status: int) -> int:
        """Get request count for testing."""
        return self._request_counts.get((upstream, method, status), 0)

    def get_scan_count(self, scanner: str, result: str) -> int:
        """Get scan count for testing."""
        return self._scan_counts.get((scanner, result), 0)

    def get_detection_count(self, category: str, action: str) -> int:
        """Get detection count for testing."""
        return self._detection_counts.get((category, action), 0)

    @staticmethod
    def generate_output() -> tuple[bytes, str]:
        """Generate Prometheus output."""
        return generate_latest(), CONTENT_TYPE_LATEST
