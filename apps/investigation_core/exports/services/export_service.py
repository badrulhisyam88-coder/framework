"""ExportService — orchestrates investigation export to knowledge-vault markdown."""

from __future__ import annotations

from typing import Any

import aiosqlite

from apps.investigation_core.exports.markdown.renderer import MarkdownRenderer
from apps.investigation_core.exports.models.export_record import ExportRecord, ExportStatus
from apps.investigation_core.exports.vault.vault_manager import VaultManager
from apps.investigation_core.progression.storage.mastery_repo import MasteryRepository
from apps.investigation_core.storage.investigation_repo import InvestigationRepository
from apps.investigation_core.storage.learning_repo import LearningProgressRepository
from apps.investigation_core.storage.timeline_repo import TimelineRepository
from apps.investigation_core.taxonomy.stages import EventType
from apps.investigation_core.timeline.recorder import TimelineRecorder
from sdk import Logger


class ExportService:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db
        self._inv_repo = InvestigationRepository(db)
        self._tl_repo = TimelineRepository(db)
        self._mastery_repo = MasteryRepository(db)
        self._lr_repo = LearningProgressRepository(db)
        self._recorder = TimelineRecorder(db)
        self._renderer = MarkdownRenderer()
        self._vault = VaultManager()

    async def generate_export(
        self,
        investigation_id: str,
        target: str,
        findings: list[Any],
        evidence: list[Any],
        guided_action_objects: list[Any] | None = None,
    ) -> ExportRecord:
        inv = await self._inv_repo.get_by_id(investigation_id)
        if not inv:
            raise ValueError(f"Investigation not found: {investigation_id!r}")

        # Gather data
        timeline_events = await self._tl_repo.list_for_investigation(investigation_id)
        mastery_records = await self._mastery_repo.list_for_investigation(investigation_id)
        all_progress = await self._lr_repo.list_for_investigation(investigation_id)

        # Separate completed vs active learning paths
        from apps.investigation_core.learning.path_registry import registry as path_reg
        completed_path_objs = [
            path_reg.get(p.path_id)
            for p in all_progress
            if str(p.status) == "completed" and path_reg.get(p.path_id)
        ]
        active_path_objs = [
            path_reg.get(p.path_id)
            for p in all_progress
            if str(p.status) == "active" and path_reg.get(p.path_id)
        ]

        # Completed guided actions
        completed_actions_obj = guided_action_objects or []

        # Themes + cross-investigation linkage (Phase 15)
        from apps.investigation_core.intelligence.engine import (
            cross_investigation_links,
            themes_for_findings,
        )
        themes = themes_for_findings(findings, evidence=evidence)
        theme_cross_links: dict[str, list] = {}
        for theme in themes:
            from apps.investigation_core.intelligence.clusters import CLUSTERS
            cluster = CLUSTERS.get(theme.theme_id)
            if cluster is None:
                continue
            try:
                theme_cross_links[theme.theme_id] = await cross_investigation_links(
                    self._db, cluster, exclude_investigation_id=investigation_id,
                )
            except Exception as exc:
                Logger.info(
                    "export.cross_links_error",
                    extra={"theme_id": theme.theme_id, "error": str(exc)},
                )
                theme_cross_links[theme.theme_id] = []

        # Render markdown
        content = self._renderer.render(
            inv,
            target,
            findings=findings,
            evidence=evidence,
            mastery_records=mastery_records,
            completed_path_objects=completed_path_objs,
            active_path_objects=active_path_objs,
            completed_action_objects=completed_actions_obj,
            timeline_events=timeline_events,
            themes=themes,
            theme_cross_links=theme_cross_links,
        )

        # Write to vault
        try:
            self._vault.ensure_investigation_dir(investigation_id)
            out_path = self._vault.investigation_report_path(investigation_id, target)
            out_path.write_text(content, encoding="utf-8")
            vault_rel = self._vault.vault_relative(out_path)
            status = ExportStatus.GENERATED
        except OSError as exc:
            Logger.info(
                "export.write_failed",
                extra={"investigation_id": investigation_id, "error": str(exc)},
            )
            out_path = None
            vault_rel = None
            status = ExportStatus.FAILED

        record = ExportRecord(
            investigation_id=investigation_id,
            export_type="investigation_summary",
            file_path=str(out_path) if out_path else None,
            vault_path=vault_rel,
            status=status,
        )
        await self._persist_record(record)

        # Timeline event
        await self._recorder.record(
            investigation_id,
            EventType.EXPORT_GENERATED,
            f"Knowledge export generated: {vault_rel or 'failed'}",
            detail={
                "export_id": record.export_id,
                "status": str(status),
                "vault_path": vault_rel,
            },
        )
        Logger.info(
            "export.generated",
            extra={
                "investigation_id": investigation_id,
                "export_id": record.export_id,
                "status": str(status),
            },
        )

        # Update investigation stage if needed
        from apps.investigation_core.services.investigation_service import (
            InvestigationService,
        )
        core_svc = InvestigationService(self._db)
        if out_path:
            await core_svc.record_knowledge_exported(investigation_id, vault_rel or str(out_path))

        return record

    async def list_exports(self, investigation_id: str) -> list[ExportRecord]:
        async with self._db.execute(
            "SELECT * FROM export_records"
            " WHERE investigation_id=? ORDER BY generated_at DESC",
            (investigation_id,),
        ) as cur:
            rows = await cur.fetchall()
        from datetime import datetime
        return [
            ExportRecord(
                export_id=r["export_id"],
                investigation_id=r["investigation_id"],
                export_type=r["export_type"],
                file_path=r["file_path"],
                vault_path=r["vault_path"],
                status=ExportStatus(r["status"]),
                generated_at=datetime.fromisoformat(r["generated_at"]),
            )
            for r in rows
        ]

    async def _persist_record(self, record: ExportRecord) -> None:
        await self._db.execute(
            """INSERT INTO export_records
               (export_id, investigation_id, export_type, file_path, vault_path,
                status, generated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                record.export_id,
                record.investigation_id,
                record.export_type,
                record.file_path,
                record.vault_path,
                str(record.status),
                record.generated_at.isoformat(),
            ),
        )
        await self._db.commit()
