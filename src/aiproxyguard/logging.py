"""Structured JSON logging with key redaction."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any


class RedactingFilter(logging.Filter):
    """Filter that redacts sensitive values from log records."""

    SENSITIVE_PATTERNS = [
        re.compile(r"(sk-[a-zA-Z0-9]+)"),
        re.compile(r"(sk-ant-[a-zA-Z0-9-]+)"),
        re.compile(r"(Bearer\s+)([a-zA-Z0-9._-]+)"),
    ]

    SENSITIVE_HEADERS = {"authorization", "api-key", "x-api-key"}

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive information from the log record."""
        if hasattr(record, "headers"):
            record.headers = self._redact_headers(record.headers)
        if record.msg:
            record.msg = self._redact_string(str(record.msg))
        return True

    def _redact_headers(self, headers: dict[str, Any]) -> dict[str, Any]:
        """Redact sensitive headers."""
        result = {}
        for key, value in headers.items():
            if key.lower() in self.SENSITIVE_HEADERS:
                result[key] = "[REDACTED]"
            else:
                result[key] = value
        return result

    def _redact_string(self, text: str) -> str:
        """Redact sensitive patterns in string."""
        for pattern in self.SENSITIVE_PATTERNS:
            text = pattern.sub("[REDACTED]", text)
        return text


class JSONFormatter(logging.Formatter):
    """JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key, value in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "created", "filename", "funcName",
                "levelname", "levelno", "lineno", "module", "msecs",
                "pathname", "process", "processName", "relativeCreated",
                "stack_info", "exc_info", "exc_text", "thread", "threadName",
                "message", "asctime",
            }:
                data[key] = value

        if record.exc_info:
            data["exception"] = self.formatException(record.exc_info)

        return json.dumps(data)


def setup_logging(
    level: str = "info",
    format: str = "json",
    handler: logging.Handler | None = None,
    redact_keys: bool = True,
) -> None:
    """Configure logging for the application."""
    root = logging.getLogger("aiproxyguard")
    root.setLevel(getattr(logging, level.upper()))

    if handler is None:
        handler = logging.StreamHandler()

    if format == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        ))

    if redact_keys:
        handler.addFilter(RedactingFilter())

    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance."""
    return logging.getLogger(f"aiproxyguard.{name}")
