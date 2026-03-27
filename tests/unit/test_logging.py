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

    def test_redacts_api_keys_in_args_tuple(self) -> None:
        """API keys passed via format args are redacted."""
        redacting_filter = RedactingFilter()

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Token: %s",
            args=("sk-secret123token",),
            exc_info=None,
        )

        redacting_filter.filter(record)
        assert record.args is not None
        assert "[REDACTED]" in record.args[0]
        assert "sk-secret123" not in record.args[0]

    def test_redacts_api_keys_in_multiple_args(self) -> None:
        """Multiple API keys in args are redacted."""
        redacting_filter = RedactingFilter()

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Auth: %s, Key: %s",
            args=("sk-secret123", "sk-ant-another-key"),
            exc_info=None,
        )

        redacting_filter.filter(record)
        assert record.args is not None
        assert "[REDACTED]" in record.args[0]
        assert "[REDACTED]" in record.args[1]

    def test_redacts_bearer_tokens_in_args(self) -> None:
        """Bearer tokens in args are redacted."""
        redacting_filter = RedactingFilter()

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Auth header: %s",
            args=("Bearer mytoken123",),
            exc_info=None,
        )

        redacting_filter.filter(record)
        assert record.args is not None
        assert "[REDACTED]" in record.args[0]
        assert "mytoken123" not in record.args[0]
