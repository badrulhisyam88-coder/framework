"""VaultManager — knowledge-vault path resolution for investigation exports.

Reuses the KNOWLEDGE_VAULT_PATH environment variable pattern from
exporters/config.py without importing it (bounded context rule).
"""

from __future__ import annotations

import os
import re
from pathlib import Path


def _get_vault_root() -> Path:
    env = os.environ.get("KNOWLEDGE_VAULT_PATH")
    if env:
        return Path(env).resolve()
    return (Path(__file__).parent.parent.parent.parent.parent
            / "knowledge-vault").resolve()


def _slugify(text: str) -> str:
    slug = text.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug)
    return slug.strip("-")[:60]


class VaultManager:
    def __init__(self) -> None:
        self._root = _get_vault_root()

    @property
    def root(self) -> Path:
        return self._root

    def investigation_dir(self, investigation_id: str) -> Path:
        return self._root / "investigations" / investigation_id[:8]

    def investigation_report_path(
        self, investigation_id: str, target: str
    ) -> Path:
        slug = _slugify(target)
        fname = f"investigation-{slug}.md"
        return self.investigation_dir(investigation_id) / fname

    def ensure_investigation_dir(self, investigation_id: str) -> Path:
        d = self.investigation_dir(investigation_id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def vault_relative(self, absolute: Path) -> str:
        try:
            return str(absolute.relative_to(self._root))
        except ValueError:
            return str(absolute)

    # ── Campaign-level paths (Phase 16) ─────────────────────────────────

    def campaign_dir(self, campaign_id: str) -> Path:
        return self._root / "campaigns" / campaign_id[:8]

    def campaign_synthesis_path(self, campaign_id: str, title: str) -> Path:
        return self.campaign_dir(campaign_id) / f"campaign-{_slugify(title)}.md"

    def ensure_campaign_dir(self, campaign_id: str) -> Path:
        d = self.campaign_dir(campaign_id)
        d.mkdir(parents=True, exist_ok=True)
        return d
