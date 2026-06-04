"""SDK logging interface."""

from typing import Any

from core.logging.setup import configure_logging, get_logger

# Module-level flag — ensures configure_logging() is called at most once
# from the SDK layer, regardless of how many Logger calls are made.
_logging_configured = False


def _ensure_logging_configured() -> None:
    global _logging_configured
    if not _logging_configured:
        from core.config.settings import get_settings
        configure_logging(get_settings().log_level)
        _logging_configured = True


class Logger:
    """Application-facing logger facade."""

    @staticmethod
    def info(message: str, **context: Any) -> None:
        _ensure_logging_configured()
        get_logger("sdk").info(message, extra=context)

    @staticmethod
    def error(message: str, **context: Any) -> None:
        _ensure_logging_configured()
        get_logger("sdk").error(message, extra=context)
