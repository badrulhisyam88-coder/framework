"""Read/write model selections from config/settings.json.

Settings file is bind-mounted at /app/config/settings.json in Docker;
falls back to the repo path when running on the host.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

_SETTINGS_PATH = Path(os.environ.get("MODEL_SETTINGS_PATH", "config/settings.json"))

LLM_MODELS = ["qwen2.5:7b-instruct"]
EMBED_MODELS = ["nomic-embed-text"]

_DEFAULTS: dict = {"llm_model": "qwen2.5:7b-instruct", "embed_model": "nomic-embed-text"}


def load() -> dict:
    """Return current settings merged over defaults. Never raises."""
    try:
        return {**_DEFAULTS, **json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))}
    except Exception:
        return dict(_DEFAULTS)


def save(llm_model: str, embed_model: str) -> None:
    """Write validated selections back to disk. Raises ValueError on unknown model."""
    if llm_model not in LLM_MODELS:
        raise ValueError(f"Unknown LLM model: {llm_model!r}")
    if embed_model not in EMBED_MODELS:
        raise ValueError(f"Unknown embedding model: {embed_model!r}")
    _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SETTINGS_PATH.write_text(
        json.dumps({"llm_model": llm_model, "embed_model": embed_model}, indent=2),
        encoding="utf-8",
    )
