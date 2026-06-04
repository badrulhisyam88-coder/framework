"""Structured logging setup using Python standard logging."""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from core.config.settings import LogLevel

STANDARD_RECORD_ATTRS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
}


class JsonFormatter(logging.Formatter):
    """JSON formatter for deterministic machine-readable logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key, value in record.__dict__.items():
            if key not in STANDARD_RECORD_ATTRS and not key.startswith("_"):
                payload[key] = to_json_safe(value)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, sort_keys=True)


def to_json_safe(value: Any) -> Any:
    """Return a JSON-safe value for logging extras."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, dict):
        return {str(key): to_json_safe(item) for key, item in sorted(value.items(), key=str)}
    if isinstance(value, list | tuple):
        return [to_json_safe(item) for item in value]
    if isinstance(value, set | frozenset):
        return [to_json_safe(item) for item in sorted(value, key=repr)]
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    value_type = type(value)
    return f"<{value_type.__module__}.{value_type.__qualname__}>"


def configure_logging(level: LogLevel = "INFO") -> None:
    """Configure root logging once with a structured formatter."""
    root_logger = logging.getLogger()
    normalized_level = getattr(logging, level, logging.INFO)
    root_logger.setLevel(normalized_level)

    if root_logger.handlers:
        for handler in root_logger.handlers:
            handler.setFormatter(JsonFormatter())
            handler.setLevel(normalized_level)
        return

    handler = logging.StreamHandler()
    handler.setLevel(normalized_level)
    handler.setFormatter(JsonFormatter())
    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger."""
    return logging.getLogger(name)
