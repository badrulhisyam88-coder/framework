"""Vault path resolution and output directory helpers for ai-assist-tool exporters."""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Vault path resolution
# ---------------------------------------------------------------------------

_VALID_CATEGORIES = frozenset({"web", "api", "network", "cloud"})


def get_vault_path() -> Path:
    """Resolve knowledge-vault root.

    Priority:
    1. KNOWLEDGE_VAULT_PATH environment variable
    2. Default: two directories up from this file's repo root, then knowledge-vault
    """
    env = os.environ.get("KNOWLEDGE_VAULT_PATH")
    if env:
        return Path(env).resolve()
    return (Path(__file__).parent.parent.parent / "knowledge-vault").resolve()


def get_findings_path(category: str) -> Path:
    if category not in _VALID_CATEGORIES:
        raise ValueError(f"category must be one of {_VALID_CATEGORIES}, got {category!r}")
    return get_vault_path() / "findings" / category


def get_remediation_path() -> Path:
    return get_vault_path() / "remediation"


def get_attack_chains_path() -> Path:
    return get_vault_path() / "attack-chains"


def ensure_output_dirs() -> None:
    """Create required vault output directories if they do not already exist."""
    vault = get_vault_path()
    for subdir in (
        "findings/web",
        "findings/api",
        "findings/network",
        "findings/cloud",
        "remediation",
        "attack-chains",
    ):
        (vault / subdir).mkdir(parents=True, exist_ok=True)
