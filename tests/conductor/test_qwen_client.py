"""V2.5 Step 1 + V2.10 PR-A — Qwen client and ping endpoint tests.

Seven tests:

Test 1: ping() returns True when Ollama mock returns 200 + qwen2.5:7b-instruct.
Test 2: ping() returns False on connection error — no exception raised.
Test 3: chat() raises QwenUnavailableError on connection failure.
Test 4: GET /admin/qwen/ping returns 200 with status=ok (client.ping True).
Test 5: GET /admin/qwen/ping returns 200 with status=unavailable (client.ping False).
Test 6: chat() payload carries temperature=0.2, num_ctx=8192 in options.
Test 7: chat() model tag is qwen2.5:7b-instruct (instruct variant, not base).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Test 1: ping() True when model listed ─────────────────────────────────────


@pytest.mark.asyncio
async def test_ping_returns_true_when_model_listed():
    """ping() must return True when Ollama responds 200 and lists qwen2.5:7b-instruct."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "models": [{"name": "qwen2.5:7b-instruct"}, {"name": "llama3:8b"}]
    }

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("apps.conductor.qwen.client.httpx.AsyncClient", return_value=mock_client), \
         patch("apps.conductor.qwen.client._active_model", return_value="qwen2.5:7b-instruct"):
        from apps.conductor.qwen.client import ping
        result = await ping()

    assert result is True


# ── Test 2: ping() False on connection error — no exception ───────────────────


@pytest.mark.asyncio
async def test_ping_returns_false_on_connection_error():
    """ping() must return False when Ollama is unreachable — must not raise."""
    import httpx

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

    with patch("apps.conductor.qwen.client.httpx.AsyncClient", return_value=mock_client):
        from apps.conductor.qwen.client import ping
        result = await ping()

    assert result is False


# ── Test 3: chat() raises QwenUnavailableError on connection failure ──────────


@pytest.mark.asyncio
async def test_chat_raises_unavailable_on_connect_error():
    """chat() must raise QwenUnavailableError when Ollama is unreachable."""
    import httpx

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

    with patch("apps.conductor.qwen.client.httpx.AsyncClient", return_value=mock_client):
        from apps.conductor.qwen.client import QwenUnavailableError, chat
        with pytest.raises(QwenUnavailableError):
            await chat([{"role": "user", "content": "hello"}])


# ── Tests 4 & 5: /admin/qwen/ping endpoint ────────────────────────────────────


def test_ping_endpoint_returns_ok_when_reachable():
    """GET /admin/qwen/ping returns 200 with status=ok when ping_details returns ok."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.admin_ui.routes import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    ok_payload = {
        "status": "ok",
        "model": "qwen2.5:7b-instruct",
        "base_url": "http://172.29.32.175:11434",
        "response_ms": 42,
    }

    with patch("apps.conductor.qwen.client.ping_details", new=AsyncMock(return_value=ok_payload)):
        resp = client.get("/admin/qwen/ping")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["model"] == "qwen2.5:7b-instruct"
    assert "response_ms" in body


def test_ping_endpoint_returns_unavailable_when_unreachable():
    """GET /admin/qwen/ping returns 200 with status=unavailable on failure."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.admin_ui.routes import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    unavail_payload = {
        "status": "unavailable",
        "base_url": "http://localhost:11434",
        "error": "Connection refused",
    }

    with patch("apps.conductor.qwen.client.ping_details", new=AsyncMock(return_value=unavail_payload)):
        resp = client.get("/admin/qwen/ping")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "unavailable"
    assert "error" in body


# ── Test 6: chat() payload carries determinism options ────────────────────────


@pytest.mark.asyncio
async def test_chat_payload_carries_determinism_options():
    """chat() must send temperature=0.2 and num_ctx=8192 in the Ollama options block."""
    captured: list[dict] = []

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"role": "assistant", "content": "ok"},
        "done": True,
    }

    async def _post(url: str, json: dict, **_kw):
        captured.append(json)
        return mock_resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=_post)

    with patch("apps.conductor.qwen.client.httpx.AsyncClient", return_value=mock_client):
        from apps.conductor.qwen import client as qwen_client
        await qwen_client.chat([{"role": "user", "content": "hello"}])

    assert captured, "no POST captured"
    opts = captured[0].get("options", {})
    assert opts.get("temperature") == 0.2, f"expected temperature=0.2, got {opts}"
    assert opts.get("num_ctx") == 8192, f"expected num_ctx=8192, got {opts}"


# ── Test 7: chat() uses instruct model tag ────────────────────────────────────


@pytest.mark.asyncio
async def test_chat_uses_instruct_model_tag():
    """chat() model field must be qwen2.5:7b-instruct (instruct variant, not base)."""
    captured: list[dict] = []

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"role": "assistant", "content": "ok"},
        "done": True,
    }

    async def _post(url: str, json: dict, **_kw):
        captured.append(json)
        return mock_resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=_post)

    # Patch _active_model so test is independent of settings.json on disk
    with patch("apps.conductor.qwen.client.httpx.AsyncClient", return_value=mock_client), \
         patch("apps.conductor.qwen.client._active_model", return_value="qwen2.5:7b-instruct"):
        from apps.conductor.qwen import client as qwen_client
        await qwen_client.chat([{"role": "user", "content": "hello"}])

    assert captured, "no POST captured"
    assert captured[0].get("model") == "qwen2.5:7b-instruct", (
        f"expected model=qwen2.5:7b-instruct, got {captured[0].get('model')}"
    )
