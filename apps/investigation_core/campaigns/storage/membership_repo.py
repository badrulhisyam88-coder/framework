"""SQLite repository for CampaignMembership records."""

from __future__ import annotations

from datetime import datetime

import aiosqlite

from apps.investigation_core.campaigns.models.campaign import CampaignStage
from apps.investigation_core.campaigns.models.membership import CampaignMembership


def _row_to_membership(row: aiosqlite.Row) -> CampaignMembership:
    return CampaignMembership(
        membership_id=row["membership_id"],
        campaign_id=row["campaign_id"],
        investigation_id=row["investigation_id"],
        stage=CampaignStage(row["stage"]),
        sequence_order=int(row["sequence_order"]),
        parent_investigation_id=row["parent_investigation_id"],
        joined_at=datetime.fromisoformat(row["joined_at"]),
        notes=row["notes"],
    )


class MembershipRepository:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def insert(self, membership: CampaignMembership) -> None:
        await self._db.execute(
            """INSERT INTO campaign_memberships
               (membership_id, campaign_id, investigation_id, stage,
                sequence_order, parent_investigation_id, joined_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                membership.membership_id,
                membership.campaign_id,
                membership.investigation_id,
                str(membership.stage),
                membership.sequence_order,
                membership.parent_investigation_id,
                membership.joined_at.isoformat(),
                membership.notes,
            ),
        )
        await self._db.commit()

    async def update_stage(
        self, campaign_id: str, investigation_id: str, stage: CampaignStage
    ) -> None:
        await self._db.execute(
            """UPDATE campaign_memberships
                  SET stage=? WHERE campaign_id=? AND investigation_id=?""",
            (str(stage), campaign_id, investigation_id),
        )
        await self._db.commit()

    async def delete(self, campaign_id: str, investigation_id: str) -> None:
        await self._db.execute(
            "DELETE FROM campaign_memberships"
            " WHERE campaign_id=? AND investigation_id=?",
            (campaign_id, investigation_id),
        )
        await self._db.commit()

    async def list_for_campaign(
        self, campaign_id: str
    ) -> list[CampaignMembership]:
        async with self._db.execute(
            "SELECT * FROM campaign_memberships"
            " WHERE campaign_id=? ORDER BY sequence_order ASC, joined_at ASC",
            (campaign_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_membership(r) for r in rows]

    async def list_for_investigation(
        self, investigation_id: str
    ) -> list[CampaignMembership]:
        async with self._db.execute(
            "SELECT * FROM campaign_memberships"
            " WHERE investigation_id=? ORDER BY joined_at ASC",
            (investigation_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_membership(r) for r in rows]

    async def get(
        self, campaign_id: str, investigation_id: str
    ) -> CampaignMembership | None:
        async with self._db.execute(
            "SELECT * FROM campaign_memberships"
            " WHERE campaign_id=? AND investigation_id=? LIMIT 1",
            (campaign_id, investigation_id),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_membership(row) if row else None
