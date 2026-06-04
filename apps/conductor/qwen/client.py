"""Qwen client — wraps Ollama HTTP API for Qwen 2.5 7B.

Base URL read from OLLAMA_BASE_URL env var at import time.
Falls back to http://localhost:11434 if not set.

V2.5 Step 1: connectivity + ping only.
"""
from __future__ import annotations

import logging
import os
import time

import httpx

logger = logging.getLogger("conductor.qwen")

OLLAMA_BASE_URL: str = (
    os.environ.get("OLLAMA_BASE_URL", "").strip() or "http://localhost:11434"
).rstrip("/")
MODEL: str = "qwen2.5:7b-instruct"  # instruct variant required; base model is non-deterministic

logger.info("Qwen client configured — base_url=%s model=%s", OLLAMA_BASE_URL, MODEL)


def _active_model() -> str:
    """Return the LLM model from config/settings.json, fallback to MODULE default."""
    try:
        from apps.admin_ui.model_settings import load
        return load()["llm_model"]
    except Exception:
        return MODEL


class QwenUnavailableError(Exception):
    """Raised when Ollama is unreachable."""


class QwenTimeoutError(Exception):
    """Raised when an Ollama request exceeds the timeout."""


async def chat(
    messages: list[dict],
    tools: list[dict] | None = None,
    timeout: int = 30,
) -> dict:
    """POST /api/chat to Ollama. Returns the parsed response dict.

    Raises:
        QwenUnavailableError: on connection failure or non-2xx response.
        QwenTimeoutError: when the request exceeds *timeout* seconds.
    """
    payload: dict = {
        "model": _active_model(),
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.2, "num_ctx": 8192},
    }
    if tools:
        payload["tools"] = tools

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload)
    except httpx.TimeoutException as exc:
        raise QwenTimeoutError(f"Ollama request timed out after {timeout}s") from exc
    except httpx.ConnectError as exc:
        raise QwenUnavailableError(f"Cannot reach Ollama at {OLLAMA_BASE_URL}: {exc}") from exc
    except httpx.HTTPError as exc:
        raise QwenUnavailableError(f"Ollama HTTP error: {exc}") from exc

    if resp.status_code >= 400:
        raise QwenUnavailableError(
            f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}"
        )

    return resp.json()


async def ping() -> bool:
    """GET /api/tags, confirm qwen2.5:7b is listed.

    Returns True if reachable and model present; False otherwise.
    Never raises — safe to call at startup or from health endpoints.
    """
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
        if resp.status_code != 200:
            return False
        models = [m.get("name", "") for m in resp.json().get("models", [])]
        return _active_model() in models
    except Exception:
        return False


async def ping_details() -> dict:
    """Like ping() but returns timing and error detail for the admin endpoint."""
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        if resp.status_code != 200:
            return {
                "status": "unavailable",
                "base_url": OLLAMA_BASE_URL,
                "error": f"HTTP {resp.status_code}",
            }
        models = [m.get("name", "") for m in resp.json().get("models", [])]
        active = _active_model()
        if active not in models:
            return {
                "status": "unavailable",
                "base_url": OLLAMA_BASE_URL,
                "error": f"model {active!r} not found — available: {models}",
            }
        return {
            "status": "ok",
            "model": active,
            "base_url": OLLAMA_BASE_URL,
            "response_ms": elapsed_ms,
        }
    except httpx.TimeoutException:
        return {"status": "unavailable", "base_url": OLLAMA_BASE_URL, "error": "timeout"}
    except Exception as exc:
        return {"status": "unavailable", "base_url": OLLAMA_BASE_URL, "error": str(exc)}
