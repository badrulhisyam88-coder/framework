"""V2.5 Step 3 — backend tests for Qwen chat endpoint and context builder.

Four tests:

Test 1: test_chat_endpoint_returns_200_with_response
  Mock client.chat(); assert 200 + response field present and non-empty.

Test 2: test_chat_endpoint_returns_200_on_unavailable
  Mock QwenUnavailableError from client.chat(); assert 200 + unavailable
  message in body (never 500).

Test 3: test_context_builder_includes_branch_states
  Seed mock DB with exploitation_branches rows; assert branch states appear
  in the context string.

Test 4: test_history_passed_to_client_chat
  Assert history messages are included in the messages list sent to chat().

Tests require fastapi + aiosqlite. Skip on bare host if unavailable.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Availability guard ────────────────────────────────────────────────────────

def _check_fastapi():
    try:
        import fastapi  # noqa: F401
        import httpx    # noqa: F401
        return True
    except ImportError:
        return False


# ── Test 1: chat endpoint returns 200 + response ──────────────────────────────


@pytest.mark.skipif(not _check_fastapi(), reason="fastapi/httpx not installed on host")
def test_chat_endpoint_returns_200_with_response():
    """POST /investigations/{id}/qwen/chat returns 200 + response field when Qwen is up.

    Defect class caught: if the endpoint raises instead of catching Qwen errors,
    the panel shows a browser-level error (no JSON) instead of the advisory message.
    """
    import asyncio
    from unittest.mock import AsyncMock, patch

    _FAKE_RESP = {
        "message": {"role": "assistant", "content": "Try credential_brute on the login form."}
    }

    async def _run():
        from apps.conductor.qwen.context_builder import build_investigation_context

        with patch("apps.conductor.qwen.client.chat", new=AsyncMock(return_value=_FAKE_RESP)) as mock_chat, \
             patch(
                "apps.conductor.qwen.context_builder.build_investigation_context",
                new=AsyncMock(return_value="Investigation target: http://test\n\nFindings: none"),
             ):
            from fastapi.testclient import TestClient
            from fastapi import FastAPI
            from apps.investigation_workspace.api.routes import router
            app = FastAPI()
            app.include_router(router, prefix="/api/v1/validation")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/validation/workspace/investigations/inv_test123/qwen/chat",
                json={"message": "What findings were discovered?", "history": []},
            )
        return resp, mock_chat

    resp, mock_chat = asyncio.get_event_loop().run_until_complete(_run())
    assert resp.status_code == 200
    data = resp.json()
    assert "response" in data
    assert "investigation_id" in data
    assert data["investigation_id"] == "inv_test123"
    assert "credential_brute" in data["response"] or len(data["response"]) > 0


@pytest.mark.skipif(not _check_fastapi(), reason="fastapi/httpx not installed on host")
def test_chat_endpoint_returns_200_on_unavailable():
    """POST /qwen/chat returns 200 with unavailable message when Qwen raises.

    Defect class caught: a 500 from Qwen propagating to the operator would
    show a browser error page instead of a friendly inline message.
    """
    import asyncio
    from apps.conductor.qwen.client import QwenUnavailableError

    async def _run():
        with patch(
            "apps.conductor.qwen.client.chat",
            new=AsyncMock(side_effect=QwenUnavailableError("connection refused")),
        ), patch(
            "apps.conductor.qwen.context_builder.build_investigation_context",
            new=AsyncMock(return_value="Investigation context unavailable."),
        ):
            from fastapi.testclient import TestClient
            from fastapi import FastAPI
            from apps.investigation_workspace.api.routes import router
            app = FastAPI()
            app.include_router(router, prefix="/api/v1/validation")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/validation/workspace/investigations/inv_down/qwen/chat",
                json={"message": "hello", "history": []},
            )
        return resp

    resp = asyncio.get_event_loop().run_until_complete(_run())
    assert resp.status_code == 200
    data = resp.json()
    assert "response" in data
    assert "unavailable" in data["response"].lower() or "qwen" in data["response"].lower()


# ── Test 3: context builder includes branch states ───────────────────────────


def _check_aiosqlite() -> bool:
    try:
        import aiosqlite  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.asyncio
@pytest.mark.skipif(not _check_aiosqlite(), reason="aiosqlite not installed on host")
async def test_context_builder_includes_branch_states():
    """build_investigation_context returns a string that includes engine states.

    Defect class caught: if the DB query returns nothing or the formatter
    omits branch state, Qwen has no context for which engines have run and
    what they produced — it cannot give actionable advice.
    """
    _BRANCHES = [
        ("credential_brute", "succeeded", '{"artifact_type":"captured_session","username":"wiener"}', None),
        ("sqli_auth_bypass",  "exhausted", None, '{"detection_method":"response_diff","payloads_tried":["payload1","payload2"]}'),
    ]
    _FINDINGS = [
        ("login_form_detected", "Login form detected", "medium", "/login", "fid_001"),
    ]

    # Build a minimal async context manager mock for get_db
    class _FakeCursor:
        def __init__(self, rows):
            self._rows = rows
        async def fetchone(self):
            return self._rows[0] if self._rows else None
        async def fetchall(self):
            return self._rows
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            pass

    class _FakeDB:
        def __init__(self, findings, branches):
            self._findings = findings
            self._branches = branches
            self._call_count = 0

        def execute(self, sql, params=None):
            if "normalized_findings" in sql:
                # Return (finding_type, title, severity, endpoint, finding_id)
                return _FakeCursor(self._findings)
            elif "exploitation_branches" in sql:
                # Return (engine_id, state, artifact, exhaustion_record)
                return _FakeCursor(self._branches)
            elif "investigations" in sql:
                return _FakeCursor([("http://testlab",)])
            return _FakeCursor([])

        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            pass

    class _DBContextManager:
        def __init__(self, findings, branches):
            self._f = findings
            self._b = branches
        async def __aenter__(self):
            return _FakeDB(self._f, self._b)
        async def __aexit__(self, *a):
            pass

    def _fake_get_db(*args, **kwargs):
        return _DBContextManager(_FINDINGS, _BRANCHES)

    # Patch at the import-time resolution point inside _build()
    with patch("apps.validation.database.get_db", side_effect=_fake_get_db):
        from apps.conductor.qwen.context_builder import build_investigation_context
        result = await build_investigation_context("inv_test_branches")

    assert "credential_brute" in result
    assert "succeeded" in result.upper() or "SUCCEEDED" in result
    assert "sqli_auth_bypass" in result
    assert "exhausted" in result.upper() or "EXHAUSTED" in result
    assert "login_form_detected" in result


# ── Test 4: history passed to client.chat ────────────────────────────────────


@pytest.mark.skipif(not _check_fastapi(), reason="fastapi/httpx not installed on host")
def test_history_passed_to_client_chat():
    """History messages from the request body are included in messages sent to chat().

    Defect class caught: if the endpoint only sends the new message (not history),
    Qwen loses conversational context — each message is treated as a fresh query
    with no awareness of the prior exchange.
    """
    import asyncio

    captured: list = []

    async def _mock_chat(messages, **kwargs):
        captured.extend(messages)
        return {"message": {"role": "assistant", "content": "Here is my advice."}}

    _HISTORY = [
        {"role": "user",      "content": "What is the target?"},
        {"role": "assistant", "content": "The target is http://testlab"},
    ]

    async def _run():
        with patch("apps.conductor.qwen.client.chat", new=_mock_chat), \
             patch(
                "apps.conductor.qwen.context_builder.build_investigation_context",
                new=AsyncMock(return_value="Investigation target: http://testlab"),
             ):
            from fastapi.testclient import TestClient
            from fastapi import FastAPI
            from apps.investigation_workspace.api.routes import router
            app = FastAPI()
            app.include_router(router, prefix="/api/v1/validation")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/validation/workspace/investigations/inv_hist/qwen/chat",
                json={"message": "What should I try next?", "history": _HISTORY},
            )
        return resp

    resp = asyncio.get_event_loop().run_until_complete(_run())
    assert resp.status_code == 200

    # captured contains the full messages list sent to chat()
    roles = [m["role"] for m in captured]
    contents = [m["content"] for m in captured]

    # Must have: system + 2 history messages + new user message
    assert "system" in roles
    assert "What is the target?" in contents
    assert "The target is http://testlab" in contents
    assert "What should I try next?" in contents
