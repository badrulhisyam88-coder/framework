"""SDK configuration interface."""

from typing import Any

from core.config.settings import get_settings


class Config:
    """Read-only configuration access for applications."""

    @staticmethod
    def get(key: str, default: Any = None) -> Any:
        settings = get_settings()
        return getattr(settings, key, default)
