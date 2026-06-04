"""V2.6 Step 1 — tests for API context enrichment in context_builder.py.

8 tests:
  test_fetch_openapi_schema_returns_parsed_on_200
  test_fetch_openapi_schema_returns_none_on_timeout
  test_fetch_openapi_schema_returns_none_on_invalid_json
  test_fetch_product_catalog_returns_list_on_200
  test_fetch_product_catalog_returns_none_on_404
  test_context_includes_api_schema_section
  test_context_graceful_degradation
  test_context_product_catalog_section

Tests that require aiosqlite: skip on host with pytest.importorskip.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── helpers ───────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


# ── Test 1 — _fetch_openapi_schema returns dict on 200 ───────────────────────


def test_fetch_openapi_schema_returns_parsed_on_200():
    """_fetch_openapi_schema returns parsed dict when server responds 200 + valid JSON."""
    from apps.conductor.qwen.context_builder import _fetch_openapi_schema

    schema = {"openapi": "3.0.0", "paths": {"/api/login": {"post": {}}}}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = schema

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    # httpx.AsyncClient is used as an async context manager
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_ctx):
        result = _run(_fetch_openapi_schema("http://target.example.com"))

    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert result.get("openapi") == "3.0.0"


# ── Test 2 — _fetch_openapi_schema returns None on timeout ───────────────────


def test_fetch_openapi_schema_returns_none_on_timeout():
    """_fetch_openapi_schema returns None (never raises) on httpx timeout."""
    import httpx
    from apps.conductor.qwen.context_builder import _fetch_openapi_schema

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_ctx):
        result = _run(_fetch_openapi_schema("http://target.example.com"))

    assert result is None, "Expected None on timeout, got non-None"


# ── Test 3 — _fetch_openapi_schema returns None on invalid JSON ───────────────


def test_fetch_openapi_schema_returns_none_on_invalid_json():
    """_fetch_openapi_schema returns None when server returns 200 but invalid JSON."""
    from apps.conductor.qwen.context_builder import _fetch_openapi_schema

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("not json")

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_ctx):
        result = _run(_fetch_openapi_schema("http://target.example.com"))

    assert result is None, "Expected None on invalid JSON, got non-None"


# ── Test 4 — _fetch_product_catalog returns list on 200 ──────────────────────


def test_fetch_product_catalog_returns_list_on_200():
    """_fetch_product_catalog returns list with first item parsed correctly."""
    from apps.conductor.qwen.context_builder import _fetch_product_catalog

    raw_products = [
        {"productId": 1, "name": "Leather Jacket", "price": 1337},
        {"productId": 2, "name": "Hoodie", "price": 42},
    ]
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = raw_products

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_ctx):
        result = _run(_fetch_product_catalog("http://target.example.com", {}))

    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert len(result) >= 1
    first = result[0]
    assert first.get("productId") == 1
    assert first.get("name") == "Leather Jacket"
    assert first.get("price") == 1337


# ── Test 5 — _fetch_product_catalog returns None on 404 ──────────────────────


def test_fetch_product_catalog_returns_none_on_404():
    """_fetch_product_catalog returns None (never raises) when both URLs return 404."""
    from apps.conductor.qwen.context_builder import _fetch_product_catalog

    mock_resp = MagicMock()
    mock_resp.status_code = 404

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_ctx):
        result = _run(_fetch_product_catalog("http://target.example.com", {}))

    assert result is None, "Expected None on 404, got non-None"


# ── Test 6 — context includes API Schema section ─────────────────────────────


def test_context_includes_api_schema_section():
    """build_investigation_context includes 'API Schema' section when schema fetched."""
    aiosqlite = pytest.importorskip("aiosqlite")  # noqa: F841

    from apps.conductor.qwen.context_builder import build_investigation_context

    schema = {
        "openapi": "3.0.0",
        "paths": {
            "/api/login": {"post": {"parameters": [{"name": "username"}]}},
            "/api/products": {"get": {}},
        },
    }

    investigation_id = "test-enrichment-v26-001"

    with (
        patch(
            "apps.conductor.qwen.context_builder._fetch_openapi_schema",
            AsyncMock(return_value=schema),
        ),
        patch(
            "apps.conductor.qwen.context_builder._fetch_product_catalog",
            AsyncMock(return_value=None),
        ),
        patch(
            "apps.conductor.qwen.context_builder._build",
            wraps=None,
        ) as mock_build,
    ):
        # We patch _build to return a controlled string that includes the
        # sections injected by _fetch_openapi_schema.
        # Simpler: patch _fetch_openapi_schema and call _build directly.
        pass

    # Direct call: patch DB and fetchers together.
    async def _fake_build(inv_id: str) -> str:
        return await _run_build_with_mocks(inv_id, schema, None)

    async def _run_build_with_mocks(inv_id, schema_val, catalog_val):
        with (
            patch(
                "apps.conductor.qwen.context_builder._fetch_openapi_schema",
                AsyncMock(return_value=schema_val),
            ),
            patch(
                "apps.conductor.qwen.context_builder._fetch_product_catalog",
                AsyncMock(return_value=catalog_val),
            ),
            patch(
                "apps.validation.database.get_db",
            ) as mock_get_db,
        ):
            # Minimal DB mock
            mock_db = AsyncMock()
            mock_cursor = AsyncMock()
            mock_cursor.fetchone = AsyncMock(return_value=(
                json.dumps(["http://target.lab"]),
            ))
            mock_cursor.fetchall = AsyncMock(return_value=[])
            mock_cursor.__aenter__ = AsyncMock(return_value=mock_cursor)
            mock_cursor.__aexit__ = AsyncMock(return_value=None)
            mock_db.execute = MagicMock(return_value=mock_cursor)
            mock_db.__aenter__ = AsyncMock(return_value=mock_db)
            mock_db.__aexit__ = AsyncMock(return_value=None)
            mock_get_db.return_value = mock_db

            from apps.conductor.qwen.context_builder import _build
            return await _build(inv_id)

    result = _run(_run_build_with_mocks(investigation_id, schema, None))
    assert "API Schema" in result, (
        f"'API Schema' section missing from context. Context:\n{result[:500]}"
    )
    assert "/api/login" in result or "/api/products" in result, (
        "No API paths from schema found in context output."
    )


# ── Test 7 — graceful degradation when all fetches fail ──────────────────────


def test_context_graceful_degradation():
    """build_investigation_context must not raise when all live fetches fail."""
    aiosqlite = pytest.importorskip("aiosqlite")  # noqa: F841

    async def _run_with_failing_fetches(inv_id):
        with (
            patch(
                "apps.conductor.qwen.context_builder._fetch_openapi_schema",
                AsyncMock(side_effect=Exception("network error")),
            ),
            patch(
                "apps.conductor.qwen.context_builder._fetch_product_catalog",
                AsyncMock(side_effect=Exception("network error")),
            ),
            patch(
                "apps.validation.database.get_db",
            ) as mock_get_db,
        ):
            mock_db = AsyncMock()
            mock_cursor = AsyncMock()
            mock_cursor.fetchone = AsyncMock(return_value=(
                json.dumps(["http://target.lab"]),
            ))
            mock_cursor.fetchall = AsyncMock(return_value=[])
            mock_cursor.__aenter__ = AsyncMock(return_value=mock_cursor)
            mock_cursor.__aexit__ = AsyncMock(return_value=None)
            mock_db.execute = MagicMock(return_value=mock_cursor)
            mock_db.__aenter__ = AsyncMock(return_value=mock_db)
            mock_db.__aexit__ = AsyncMock(return_value=None)
            mock_get_db.return_value = mock_db

            from apps.conductor.qwen.context_builder import build_investigation_context
            return await build_investigation_context(inv_id)

    # Must not raise — graceful degradation
    result = _run(_run_with_failing_fetches("test-degradation-001"))
    assert isinstance(result, str), "Expected string result even on fetch failure"
    # The outer wrapper catches exceptions from _build; if _build raises
    # due to the patched side_effect, the fallback "unavailable" string is returned.
    # Either a valid context or the fallback is acceptable — the key is no exception.


# ── Test 8 — product catalog section appears in context ──────────────────────


def test_context_product_catalog_section():
    """build_investigation_context includes 'Product catalog' section when catalog fetched."""
    aiosqlite = pytest.importorskip("aiosqlite")  # noqa: F841

    catalog = [
        {"productId": 7, "name": "Test Widget", "price": 99.99},
    ]

    async def _run_with_catalog(inv_id):
        with (
            patch(
                "apps.conductor.qwen.context_builder._fetch_openapi_schema",
                AsyncMock(return_value=None),
            ),
            patch(
                "apps.conductor.qwen.context_builder._fetch_product_catalog",
                AsyncMock(return_value=catalog),
            ),
            patch(
                "apps.validation.database.get_db",
            ) as mock_get_db,
        ):
            mock_db = AsyncMock()
            mock_cursor = AsyncMock()
            mock_cursor.fetchone = AsyncMock(return_value=(
                json.dumps(["http://target.lab"]),
            ))
            mock_cursor.fetchall = AsyncMock(return_value=[])
            mock_cursor.__aenter__ = AsyncMock(return_value=mock_cursor)
            mock_cursor.__aexit__ = AsyncMock(return_value=None)
            mock_db.execute = MagicMock(return_value=mock_cursor)
            mock_db.__aenter__ = AsyncMock(return_value=mock_db)
            mock_db.__aexit__ = AsyncMock(return_value=None)
            mock_get_db.return_value = mock_db

            from apps.conductor.qwen.context_builder import _build
            return await _build(inv_id)

    result = _run(_run_with_catalog("test-catalog-001"))
    assert "Product catalog" in result, (
        f"'Product catalog' section missing from context. Context:\n{result[:500]}"
    )
    assert "Test Widget" in result, "Product name missing from catalog section."
