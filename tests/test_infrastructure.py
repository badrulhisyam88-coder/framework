"""Infrastructure smoke tests — validates core health API, settings, and logging."""

import json
import logging

import pytest
from fastapi.testclient import TestClient

from core.api.app import create_app
from core.config.settings import Settings, get_settings
from core.logging.setup import JsonFormatter, configure_logging, get_logger

# =========================================================
# Fixtures
# =========================================================

@pytest.fixture(scope="module")
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


@pytest.fixture(scope="module")
def settings() -> Settings:
    return get_settings()


# =========================================================
# Health API
# =========================================================

def test_health_bare_route_returns_200(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200


def test_health_bare_route_returns_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.json()["status"] == "ok"


def test_health_bare_route_contains_required_fields(client: TestClient) -> None:
    body = client.get("/health").json()
    assert "status" in body
    assert "service" in body
    assert "version" in body
    assert "environment" in body


def test_health_prefixed_route_returns_200(client: TestClient, settings: Settings) -> None:
    response = client.get(f"{settings.api_prefix}/health")
    assert response.status_code == 200


def test_health_prefixed_route_returns_ok(client: TestClient, settings: Settings) -> None:
    response = client.get(f"{settings.api_prefix}/health")
    assert response.json()["status"] == "ok"


def test_health_response_reflects_settings(client: TestClient, settings: Settings) -> None:
    body = client.get("/health").json()
    assert body["service"] == settings.app_name
    assert body["version"] == settings.version
    assert body["environment"] == settings.environment


# =========================================================
# Settings
# =========================================================

def test_settings_environment_is_valid_literal(settings: Settings) -> None:
    valid = {"development", "test", "staging", "production"}
    assert settings.environment in valid


def test_settings_log_level_is_valid_literal(settings: Settings) -> None:
    valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    assert settings.log_level in valid


def test_settings_api_prefix_starts_with_slash(settings: Settings) -> None:
    assert settings.api_prefix.startswith("/")


def test_settings_debug_is_bool(settings: Settings) -> None:
    assert isinstance(settings.debug, bool)


# =========================================================
# Logging
# =========================================================

def test_configure_logging_adds_handler_to_root_logger() -> None:
    # Reset root logger handlers to test idempotent add
    root = logging.getLogger()
    original_handlers = root.handlers[:]
    root.handlers.clear()

    configure_logging("INFO")

    assert len(root.handlers) > 0

    # Restore state so other tests are not affected
    root.handlers.clear()
    root.handlers.extend(original_handlers)


def test_configure_logging_is_idempotent() -> None:
    root = logging.getLogger()
    original_handlers = root.handlers[:]
    root.handlers.clear()

    configure_logging("INFO")
    count_after_first = len(root.handlers)

    configure_logging("INFO")
    count_after_second = len(root.handlers)

    assert count_after_first == count_after_second

    root.handlers.clear()
    root.handlers.extend(original_handlers)


def test_json_formatter_produces_valid_json() -> None:
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="test message",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_json_formatter_contains_required_fields() -> None:
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="test message",
        args=(),
        exc_info=None,
    )
    parsed = json.loads(formatter.format(record))
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "logger" in parsed
    assert "message" in parsed


def test_get_logger_returns_named_logger() -> None:
    logger = get_logger("my-test-logger")
    assert logger.name == "my-test-logger"
