"""CampaignSynthesisService — render and persist campaign-level markdown.

Reuses the existing markdown environment + vault manager. Produces a
campaign-{slug}.md under campaigns/{campaign_id_prefix}/ with rich Obsidian
[[Investigation —]], [[Theme —]], and [[Remediation —]] wikilinks so the
campaign forms the hub of a knowledge subgraph.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import aiosqlite
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from apps.investigation_core.campaigns.models.campaign import (
    CAMPAIGN_STATUS_LABELS,
    STAGE_LABELS,
)
from apps.investigation_core.campaigns.services.campaign_service import CampaignService
from apps.investigation_core.exports.vault.vault_manager import VaultManager
from apps.investigation_core.storage.investigation_repo import InvestigationRepository
from sdk import Logger

_TEMPLATE_DIR = Path(__file__).parent.parent.parent / "exports" / "templates"
_TEMPLATE_NAME = "campaign_synthesis.md.j2"


class CampaignSynthesisService:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db
        self._campaign_svc = CampaignService(db)
        self._vault = VaultManager()
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            undefined=StrictUndefined,
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

    async def synthesize(self, campaign_id: str) -> dict:
        campaign = await self._campaign_svc.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign not found: {campaign_id!r}")

        members = await self._campaign_svc.list_members(campaign_id)
        snapshot = await self._campaign_svc.progress_snapshot(campaign_id)

        inv_repo = InvestigationRepository(self._db)
        member_views = []
        for m in members:
            inv = await inv_repo.get_by_id(m.investigation_id)
            member_views.append({
                "membership": m,
                "investigation_title": inv.title if inv else m.investigation_id[:8],
            })

        # Tags: theme-id slugs + campaign status
        tags = [f"status-{campaign.status}"]
        for t in snapshot.aggregated_themes:
            tag = f"theme-{t.cluster_id.replace('_', '-')}"
            if tag not in tags:
                tags.append(tag)

        template = self._env.get_template(_TEMPLATE_NAME)
        content = template.render(
            campaign=campaign,
            members=member_views,
            snapshot=snapshot,
            tags=tags,
            stage_labels=STAGE_LABELS,
            status_label=CAMPAIGN_STATUS_LABELS[campaign.status],
            export_date=datetime.utcnow().strftime("%Y-%m-%d"),
        )

        try:
            self._vault.ensure_campaign_dir(campaign_id)
            out_path = self._vault.campaign_synthesis_path(campaign_id, campaign.title)
            out_path.write_text(content, encoding="utf-8")
            vault_rel = self._vault.vault_relative(out_path)
            status = "generated"
        except OSError as exc:
            Logger.info(
                "campaign_synthesis.write_failed",
                extra={"campaign_id": campaign_id, "error": str(exc)},
            )
            out_path = None
            vault_rel = None
            status = "failed"

        Logger.info(
            "campaign_synthesis.generated",
            extra={"campaign_id": campaign_id, "status": status},
        )
        return {
            "campaign_id": campaign_id,
            "status": status,
            "vault_path": vault_rel,
            "file_path": str(out_path) if out_path else None,
        }
