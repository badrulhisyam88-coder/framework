"""SQLite repository for InvestigationCampaign records."""

from __future__ import annotations

import json
from datetime import datetime

import aiosqlite

from apps.investigation_core.campaigns.models.campaign import (
    CampaignStatus,
    InvestigationCampaign,
)
from apps.investigation_core.campaigns.models.objective import CampaignObjective


def _row_to_campaign(row: aiosqlite.Row) -> InvestigationCampaign:
    objs_raw = json.loads(row["objectives"] or "[]")
    objectives = [CampaignObjective.model_validate(o) for o in objs_raw]
    return InvestigationCampaign(
        campaign_id=row["campaign_id"],
        title=row["title"],
        description=row["description"] or "",
        status=CampaignStatus(row["status"]),
        objectives=objectives,
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        created_by=row["created_by"],
    )


class CampaignRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def insert(self, campaign: InvestigationCampaign) -> None:
        await self._db.execute(
            """INSERT INTO investigation_campaigns
               (campaign_id, title, description, status, objectives,
                created_at, updated_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                campaign.campaign_id,
                campaign.title,
                campaign.description,
                str(campaign.status),
                json.dumps([o.model_dump(mode="json") for o in campaign.objectives]),
                campaign.created_at.isoformat(),
                campaign.updated_at.isoformat(),
                campaign.created_by,
            ),
        )
        await self._db.commit()

    async def update(self, campaign: InvestigationCampaign) -> None:
        campaign.updated_at = datetime.utcnow()
        await self._db.execute(
            """UPDATE investigation_campaigns
                  SET title=?, description=?, status=?, objectives=?, updated_at=?
                WHERE campaign_id=?""",
            (
                campaign.title,
                campaign.description,
                str(campaign.status),
                json.dumps([o.model_dump(mode="json") for o in campaign.objectives]),
                campaign.updated_at.isoformat(),
                campaign.campaign_id,
            ),
        )
        await self._db.commit()

    async def get_by_id(self, campaign_id: str) -> InvestigationCampaign | None:
        async with self._db.execute(
            "SELECT * FROM investigation_campaigns WHERE campaign_id=?",
            (campaign_id,),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_campaign(row) if row else None

    async def list_all(self, limit: int = 200) -> list[InvestigationCampaign]:
        async with self._db.execute(
            "SELECT * FROM investigation_campaigns"
            " ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_campaign(r) for r in rows]

    async def delete(self, campaign_id: str) -> None:
        await self._db.execute(
            "DELETE FROM campaign_memberships WHERE campaign_id=?",
            (campaign_id,),
        )
        await self._db.execute(
            "DELETE FROM investigation_campaigns WHERE campaign_id=?",
            (campaign_id,),
        )
        await self._db.commit()
