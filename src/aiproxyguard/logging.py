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
        # Also redact args to prevent secrets passed via format strings
        # e.g., logger.info("Token %s", token) would leak the token
        if record.args:
            record.args = self._redact_args(record.args)
        return True

    def _redact_args(self, args: tuple | dict) -> tuple | dict:
        """Redact sensitive patterns in log arguments."""
        if isinstance(args, dict):
            return {k: self._redact_value(v) for k, v in args.items()}
        return tuple(self._redact_value(arg) for arg in args)

    def _redact_value(self, value: Any) -> Any:
        """Redact sensitive patterns in a single value."""
        if isinstance(value, str):
            return self._redact_string(value)
        return value

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


def update_logging(
    level: str | None = None,
    format: str | None = None,
    redact_keys: bool | None = None,
) -> None:
    """Update logging configuration at runtime.

    Args:
        level: New log level (debug, info, warning, error)
        format: Log format (json, text)
        redact_keys: Whether to redact sensitive keys
    """
    root = logging.getLogger("aiproxyguard")

    if level is not None:
        new_level = getattr(logging, level.upper(), None)
        if new_level is not None:
            root.setLevel(new_level)
            get_logger("logging").info(
                "Log level updated",
                extra={"new_level": level},
            )

    # Format and redaction changes require handler reconfiguration
    if format is not None or redact_keys is not None:
        for handler in root.handlers:
            # Update format if specified
            if format is not None:
                if format == "json":
                    handler.setFormatter(JSONFormatter())
                else:
                    handler.setFormatter(logging.Formatter(
                        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                    ))

            # Update redaction filter if specified
            if redact_keys is not None:
                # Remove existing redaction filters
                handler.filters = [
                    f for f in handler.filters
                    if not isinstance(f, RedactingFilter)
                ]
                # Add new filter if enabled
                if redact_keys:
                    handler.addFilter(RedactingFilter())

        if format is not None:
            get_logger("logging").info(
                "Log format updated",
                extra={"new_format": format},
            )
