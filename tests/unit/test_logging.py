"""Tests for structured logging."""

import json
import logging
from io import StringIO

from aiproxyguard.logging import setup_logging, get_logger, RedactingFilter


class TestStructuredLogging:
    """Test structured logging setup."""

    def test_json_format(self) -> None:
        """Logs are JSON formatted."""
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        setup_logging(level="info", format="json", handler=handler)

        logger = get_logger("test")
        logger.info("test message", extra={"key": "value"})

        output = stream.getvalue()
        data = json.loads(output.strip())
        assert data["message"] == "test message"
        assert data["key"] == "value"

    def test_redacts_api_keys(self) -> None:
        """API keys are redacted from logs."""
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(RedactingFilter())
        setup_logging(level="info", format="json", handler=handler)

        logger = get_logger("test")
        logger.info("request", extra={"headers": {"Authorization": "Bearer sk-secret123"}})

        output = stream.getvalue()
        assert "sk-secret123" not in output
        assert "[REDACTED]" in output
