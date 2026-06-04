"""OrchestrationService — coordinates scanner adapters, normalization,
and investigation integration."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import aiosqlite

from apps.investigation_core.evidence.models.artifact import ArtifactType
from apps.investigation_core.evidence.services.evidence_service import EvidenceService
from apps.investigation_core.services.investigation_service import InvestigationService
from apps.scanner_orchestration.adapters.nmap_adapter import NmapAdapter
from apps.scanner_orchestration.adapters.nuclei_adapter import NucleiAdapter
from apps.scanner_orchestration.adapters.zap_adapter import ZAPAdapter
from apps.scanner_orchestration.execution.models import ScanExecution, ScanStatus
from apps.scanner_orchestration.normalization.models import NormalizedFinding
from apps.scanner_orchestration.storage.finding_repo import NormalizedFindingRepository
from apps.scanner_orchestration.storage.scan_repo import ScanRepository

# ── Stubs for modules removed in PR VESTIGE-1 ────────────────────────────────

from dataclasses import dataclass as _dc

profile_registry: dict = {}


@_dc
class InvestigationRun:
    group_id: str | None
    profile_id: str
    target: str
    scans: list

    @property
    def confidence(self) -> str:
        terminal = [s for s in self.scans if s.is_terminal]
        if not terminal:
            return "pending"
        return "error" if any(str(s.status) == "failed" for s in terminal) else "ok"

    @property
    def confidence_message(self) -> str:
        counts = sum(getattr(s, "findings_count", 0) for s in self.scans)
        return f"{counts} finding(s)" if counts else ""

    @property
    def is_terminal(self) -> bool:
        return bool(self.scans) and all(s.is_terminal for s in self.scans)

    @property
    def created_at(self):
        return self.scans[0].created_at if self.scans else None


class ScanTimelineRecorder:
    def __init__(self, db: Any) -> None: ...
    async def scan_queued(self, scan: Any) -> None: pass
    async def target_resolved(self, *a: Any, **kw: Any) -> None: pass
    async def target_fingerprinted(self, *a: Any, **kw: Any) -> None: pass
    async def target_unreachable(self, *a: Any, **kw: Any) -> None: pass
    async def target_reachable(self, *a: Any, **kw: Any) -> None: pass
    async def scan_started(self, scan: Any) -> None: pass
    async def findings_normalized(self, scan: Any, types: Any) -> None: pass
    async def scan_completed(self, scan: Any) -> None: pass
    async def scan_failed(self, scan: Any) -> None: pass


class NormalizationPipeline:
    def normalize(self, raw_result: Any, scan: Any) -> list:
        return []

    async def enrich_cves_async(self, findings: list, db: Any) -> list:
        return findings
from apps.validation.database import get_db
from sdk import Logger

_ADAPTER_MAP = {
    "nmap": NmapAdapter,
    "zap": ZAPAdapter,
    "nuclei": NucleiAdapter,
}


class OrchestrationService:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db
        self._scan_repo = ScanRepository(db)
        self._finding_repo = NormalizedFindingRepository(db)
        self._pipeline = NormalizationPipeline()
        self._tl = ScanTimelineRecorder(db)
        self._inv_svc = InvestigationService(db)
        self._ev_svc = EvidenceService(db)

    async def start_scan(
        self,
        investigation_id: str,
        scanner_type: str,
        target: str,
        profile_id: str = "quick_web_scan",
        extra_config: dict[str, Any] | None = None,
    ) -> ScanExecution:
        """Queue a scan and launch it as a background task. Returns immediately."""
        profile = profile_registry.get(profile_id)
        config = {}
        if profile and scanner_type in profile.config:
            config.update(profile.config[scanner_type])
        if extra_config:
            config.update(extra_config)

        scan = ScanExecution(
            investigation_id=investigation_id,
            scanner_type=scanner_type,
            target=target,
            profile=profile_id,
            config=config,
        )
        await self._scan_repo.insert(scan)
        await self._tl.scan_queued(scan)

        # Fire-and-forget background task
        asyncio.create_task(self._run_scan_background(scan))

        Logger.info(
            "scan.queued",
            extra={
                "scan_id": scan.scan_id,
                "investigation_id": investigation_id,
                "scanner": scanner_type,
                "target": target,
            },
        )
        return scan

    async def get_scan(self, scan_id: str) -> ScanExecution | None:
        return await self._scan_repo.get_by_id(scan_id)

    async def list_scans(
        self, investigation_id: str, limit: int = 20
    ) -> list[ScanExecution]:
        return await self._scan_repo.list_for_investigation(investigation_id, limit)

    async def list_findings(
        self, scan_id: str
    ) -> list[NormalizedFinding]:
        return await self._finding_repo.list_for_scan(scan_id)

    async def list_all_findings(
        self, investigation_id: str
    ) -> list[NormalizedFinding]:
        return await self._finding_repo.list_for_investigation(investigation_id)

    async def check_adapter_available(self, scanner_type: str) -> bool:
        cls = _ADAPTER_MAP.get(scanner_type)
        if not cls:
            return False
        adapter = cls()
        return await adapter.check_available()

    # ── Investigation run (multi-scanner group) ───────────────────────────

    async def start_investigation_run(
        self,
        investigation_id: str,
        profile_id: str,
        target: str,
    ) -> tuple[str, list[ScanExecution]]:
        """Create one ScanExecution per scanner in the profile, linked by a shared
        group_id, then execute them sequentially in a background task.

        Returns (group_id, list_of_queued_scans) immediately — does not wait for
        execution to complete.
        """
        from uuid import uuid4
        profile = profile_registry.get(profile_id)
        scanner_list = profile.scanners if profile else list(_ADAPTER_MAP.keys())
        profile_config = profile.config if profile else {}

        group_id = str(uuid4())
        scans: list[ScanExecution] = []

        for scanner_type in scanner_list:
            config: dict[str, Any] = {}
            if scanner_type in profile_config:
                config.update(profile_config[scanner_type])

            scan = ScanExecution(
                investigation_id=investigation_id,
                scanner_type=scanner_type,
                target=target,
                profile=profile_id,
                config=config,
                group_id=group_id,
            )
            await self._scan_repo.insert(scan)
            await self._tl.scan_queued(scan)
            scans.append(scan)

        Logger.info(
            "group.queued",
            extra={
                "group_id": group_id,
                "profile": profile_id,
                "scanners": scanner_list,
                "investigation_id": investigation_id,
                "stages": len(scans),
            },
        )
        asyncio.create_task(self._run_group_background(group_id, scans))
        return group_id, scans

    async def list_run_findings(
        self, group_id: str
    ) -> list[NormalizedFinding]:
        """Aggregate findings from all scans in a run with conservative deduplication.

        Deduplication key: (finding_type, target, port, endpoint-path).
        When two findings share a key, the one with higher severity is kept.
        This is deterministic — no fuzzy matching or AI clustering.
        """
        _SEV_RANK: dict[str, int] = {
            "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
        }
        scans = await self._scan_repo.list_by_group(group_id)
        all_findings: list[NormalizedFinding] = []
        for scan in scans:
            all_findings.extend(await self._finding_repo.list_for_scan(scan.scan_id))

        seen: dict[tuple, NormalizedFinding] = {}
        for f in all_findings:
            # Strip query params from endpoint for dedup key
            ep = (f.endpoint or "").split("?")[0]
            key = (f.finding_type, f.target, f.port or 0, ep)
            existing = seen.get(key)
            if not existing or _SEV_RANK.get(f.severity, 0) > _SEV_RANK.get(existing.severity, 0):
                seen[key] = f

        return sorted(
            seen.values(),
            key=lambda f: (-_SEV_RANK.get(f.severity, 0), f.created_at),
        )

    async def list_runs(
        self, investigation_id: str, limit: int = 10
    ) -> list[InvestigationRun]:
        """Return scan executions grouped by group_id as InvestigationRun objects.

        Scans with no group_id (legacy single launches) each form their own run.
        Runs are sorted most-recent-first.
        """
        from collections import defaultdict

        scans = await self._scan_repo.list_for_investigation(investigation_id, limit=50)

        groups: dict[str | None, list[ScanExecution]] = defaultdict(list)
        for scan in scans:
            groups[scan.group_id].append(scan)

        runs: list[InvestigationRun] = []
        for group_id, group_scans in groups.items():
            runs.append(
                InvestigationRun(
                    group_id=group_id,
                    profile_id=group_scans[0].profile,
                    target=group_scans[0].target,
                    scans=group_scans,
                )
            )

        runs.sort(key=lambda r: r.created_at, reverse=True)
        return runs[:limit]

    # ── Background execution ──────────────────────────────────────────────

    async def _run_scan_background(self, scan: ScanExecution) -> None:
        """Executed as asyncio task — runs the full scan lifecycle."""
        async with get_db() as db:
            svc = OrchestrationService(db)
            await svc._execute(scan)

    async def _run_group_background(
        self, group_id: str, scans: list[ScanExecution]
    ) -> None:
        """Execute scans sequentially within a run group.

        A stage failure does NOT abort subsequent stages — the investigation
        continues with degraded confidence. Each stage gets its own fresh
        DB connection via _execute's internal svc.
        """
        for scan in scans:
            try:
                async with get_db() as db:
                    svc = OrchestrationService(db)
                    await svc._execute(scan)
            except Exception as exc:
                Logger.error(
                    "group.stage_failed",
                    extra={
                        "group_id": group_id,
                        "scan_id": scan.scan_id,
                        "scanner": scan.scanner_type,
                        "error": str(exc)[:200],
                    },
                )
                # Continue to next stage — degraded execution is explicit in status

    async def _execute(self, scan: ScanExecution) -> None:
        try:
            from apps.scanner_orchestration.target_resolution.diagnostics import DiagnosticsService
            from apps.scanner_orchestration.target_resolution.resolver import TargetResolver
        except ImportError as _e:
            raise RuntimeError(
                "Target resolution modules unavailable (removed in VESTIGE-1)"
            ) from _e

        scan_repo = self._scan_repo

        try:
            # ── Resolve target ────────────────────────────────────────────
            resolver = TargetResolver()
            ctx = resolver.resolve(scan.target)
            await self._tl.target_resolved(
                scan.investigation_id,
                ctx.display_url,
                ctx.scanner_url,
                str(ctx.resolution_strategy),
                scan.scan_id,
            )
            Logger.info(
                "scan.target_resolved",
                extra={
                    "display_url": ctx.display_url,
                    "scanner_url": ctx.scanner_url,
                    "strategy": str(ctx.resolution_strategy),
                    "scanner": scan.scanner_type,
                },
            )

            # ── Validate reachability + fingerprint ───────────────────────
            diag_svc = DiagnosticsService()
            ctx = await diag_svc.run(ctx)

            if ctx.fingerprint:
                await self._tl.target_fingerprinted(
                    scan.investigation_id,
                    ctx.scanner_url,
                    ctx.fingerprint,
                    ctx.fingerprint_confidence,
                    scan.scan_id,
                )

            if not ctx.reachable:
                error_msg = (
                    ctx.diagnostics.get("http", {}).get("error")
                    or ctx.diagnostics.get("tcp", {}).get("error")
                    or "Target unreachable"
                )
                await self._tl.target_unreachable(
                    scan.investigation_id,
                    ctx.scanner_url,
                    error_msg,
                    scan.scan_id,
                )
                raise RuntimeError(
                    f"Target unreachable: {ctx.scanner_url} — {error_msg}"
                )

            await self._tl.target_reachable(
                scan.investigation_id,
                ctx.scanner_url,
                ctx.fingerprint,
                ctx.latency_ms,
                scan.scan_id,
            )

            # ── Mark running ──────────────────────────────────────────────
            now = datetime.utcnow()
            await scan_repo.update_status(
                scan.scan_id, ScanStatus.RUNNING, started_at=now
            )
            scan.status = ScanStatus.RUNNING
            scan.started_at = now
            await self._tl.scan_started(scan)

            # ── Run adapter with resolved context ─────────────────────────
            cls = _ADAPTER_MAP.get(scan.scanner_type)
            if not cls:
                raise ValueError(f"Unknown scanner type: {scan.scanner_type!r}")
            adapter = cls()
            raw_result = await adapter.run_scan(ctx, scan.config)

            # Capture skip reason before normalization so it surfaces in the UI.
            # Adapters return {"skipped": True, "reason": "..."} when unavailable.
            skip_reason: str | None = None
            if raw_result.get("skipped"):
                skip_reason = raw_result.get("reason") or "Scanner was skipped"
                Logger.info(
                    "scan.scanner_skipped",
                    extra={
                        "scan_id": scan.scan_id,
                        "scanner": scan.scanner_type,
                        "reason": skip_reason,
                    },
                )

            # Stage 1: normalise + skill/learning-path enrichment (sync)
            findings = self._pipeline.normalize(raw_result, scan)

            # Stage 2: CVE intelligence enrichment (async, reads from cves table).
            # Reads apps/validation/ cves table; never writes to it.
            findings = await self._pipeline.enrich_cves_async(findings, self._db)

            # Persist findings + evidence
            await self._persist_findings(scan, findings)

            # Update scan record
            completed_at = datetime.utcnow()
            await scan_repo.update_status(
                scan.scan_id,
                ScanStatus.COMPLETED,
                completed_at=completed_at,
                findings_count=len(findings),
                error_message=skip_reason,  # None when scanner ran normally
            )
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = completed_at
            scan.findings_count = len(findings)

            # Timeline
            finding_types = list({f.finding_type for f in findings})
            await self._tl.findings_normalized(scan, finding_types)
            await self._tl.scan_completed(scan)

            # Sync skills/mastery
            await self._sync_skills(scan.investigation_id)

            Logger.info(
                "scan.completed",
                extra={
                    "scan_id": scan.scan_id,
                    "findings": len(findings),
                    "scanner": scan.scanner_type,
                },
            )

        except Exception as exc:
            Logger.error(
                "scan.failed",
                extra={"scan_id": scan.scan_id, "error": str(exc)},
            )
            await scan_repo.update_status(
                scan.scan_id,
                ScanStatus.FAILED,
                completed_at=datetime.utcnow(),
                error_message=str(exc)[:500],
            )
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
            await self._tl.scan_failed(scan)

    async def _persist_findings(
        self,
        scan: ScanExecution,
        findings: list[NormalizedFinding],
    ) -> None:
        for finding in findings:
            # Create evidence artifact BEFORE inserting the finding so that
            # finding.evidence_refs is populated when it hits the database.
            content = (
                f"Finding: {finding.title}\n"
                f"Type: {finding.finding_type}\n"
                f"Severity: {finding.severity}\n"
                f"Target: {finding.target}"
            )
            if finding.port:
                content += f"\nPort: {finding.port}"
            if finding.endpoint:
                content += f"\nEndpoint: {finding.endpoint}"
            if finding.description:
                content += f"\n\n{finding.description[:400]}"

            artifact = await self._ev_svc.capture(
                scan.investigation_id,
                ArtifactType.NOTE,
                f"[{scan.scanner_type.upper()}] {finding.title}",
                content,
                description=(
                    f"{finding.severity.capitalize()} {finding.finding_type} "
                    f"from {scan.scanner_type} scan"
                ),
                guided_action_id=None,
                tags=[scan.scanner_type, finding.finding_type, finding.severity],
            )
            finding.evidence_refs.append(artifact.evidence_id)

            # Insert finding with evidence_refs now populated
            await self._finding_repo.insert(finding)

            # Record finding in investigation core
            await self._inv_svc.record_finding_detected(
                scan.investigation_id,
                finding.finding_id,
                finding.finding_type,
                finding.severity,
            )

    async def _sync_skills(self, investigation_id: str) -> None:
        """Trigger mastery sync after new findings arrive."""
        try:
            from apps.investigation_core.evidence.storage.artifact_repo import (
                ArtifactRepository,
            )
            from apps.investigation_core.guided_actions.approvals.approval_service import (
                ApprovalService,
            )
            from apps.investigation_core.guided_actions.models.approval import ApprovalStatus
            from apps.investigation_core.progression.tracking.mastery_tracker import (
                MasteryTracker,
            )
            from apps.investigation_core.storage.learning_repo import (
                LearningProgressRepository,
            )

            inv = await self._inv_svc.get_by_id(investigation_id)
            if not inv:
                return

            finding_types = await self._inv_svc._finding_types_for_investigation(inv)
            # Also include types from normalized_findings table
            norm_types = await self._finding_repo.distinct_finding_types(investigation_id)
            all_types = list(set(finding_types + norm_types))

            lr_repo = LearningProgressRepository(self._db)
            all_progress = await lr_repo.list_for_investigation(investigation_id)
            completed_paths = [p.path_id for p in all_progress if str(p.status) == "completed"]

            art_repo = ArtifactRepository(self._db)
            artifacts = await art_repo.list_for_investigation(investigation_id)
            artifact_types = [str(a.artifact_type) for a in artifacts]

            approval_svc = ApprovalService(self._db)
            approvals = await approval_svc.list_approvals(investigation_id)
            completed_actions = [
                a.action_id for a in approvals if a.status == ApprovalStatus.COMPLETED
            ]

            tracker = MasteryTracker(self._db)
            await tracker.sync_investigation(
                investigation_id,
                all_types,
                artifact_types,
                completed_paths,
                completed_actions,
            )
        except Exception as exc:
            Logger.info(
                "scan.skill_sync_error",
                extra={"investigation_id": investigation_id, "error": str(exc)},
            )
