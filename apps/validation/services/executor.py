"""
Executor service.

Runs approved queue items through the appropriate plugin.
Single controlled attempt. Records evidence. Stores finding.

This is the only place plugins are invoked.
Nothing runs without queue_item.status == 'approved'.
"""

from __future__ import annotations

import asyncio
import importlib
import time

from apps.validation.config import clamp_workers, get_default_workers
from apps.validation.database import get_db
from apps.validation.models import (
    Evidence,
    Finding,
    FindingSeverity,
    FindingStatus,
    HistoryAction,
    HistoryEntry,
    QueueItem,
    QueueStatus,
    ValidationStatus,
    cvss_to_severity,
)
from apps.validation.repositories import (
    CVERepository,
    FindingRepository,
    HistoryRepository,
    KnownIssueRepository,
    QueueRepository,
    ServiceRepository,
)
from apps.validation.services.suppression import first_matching_rule
from sdk import Logger

# Plugin registry — maps plugin_name to module path
PLUGIN_REGISTRY = {
    "ssh_plugin": "apps.validation.plugins.ssh",
    "web_plugin": "apps.validation.plugins.web",
    "wordpress_plugin": "apps.validation.plugins.wordpress",
    "drupal_plugin": "apps.validation.plugins.drupal",
    "apache_plugin": "apps.validation.plugins.apache",
    "nginx_plugin": "apps.validation.plugins.nginx",
    "telnet_plugin": "apps.validation.plugins.telnet",
    "smb_plugin": "apps.validation.plugins.smb",
    "sqli_plugin": "apps.validation.plugins.sqli",
    "generic_plugin": "apps.validation.plugins.generic",
}


class ExecutorService:
    """
    Execute an approved queue item.

    Usage:
        executor = ExecutorService()
        finding = await executor.execute(queue_item_id)
    """

    async def execute(self, queue_item_id: str) -> Finding | None:
        async with get_db() as db:
            queue_repo = QueueRepository(db)
            item = await queue_repo.get_by_id(queue_item_id)

        if not item:
            Logger.error("executor.item_not_found", extra={"id": queue_item_id})
            return None

        if item.status != QueueStatus.APPROVED:
            Logger.error(
                "executor.not_approved",
                extra={"id": queue_item_id, "status": item.status},
            )
            return None

        # Mark as running
        async with get_db() as db:
            queue_repo = QueueRepository(db)
            await queue_repo.set_running(queue_item_id)

        Logger.info(
            "executor.start",
            extra={"id": queue_item_id, "plugin": item.plugin_name, "type": item.validation_type},
        )

        try:
            finding = await self._run_plugin(item)
        except Exception as e:
            Logger.error("executor.plugin_error", extra={"id": queue_item_id, "error": str(e)})
            async with get_db() as db:
                queue_repo = QueueRepository(db)
                await queue_repo.set_failed(queue_item_id, str(e)[:500])
            return None

        # Suppression: if any user-taught known_issue matches, mark suppressed
        # before persisting so the finding never appears in the open list.
        async with get_db() as db:
            known_repo = KnownIssueRepository(db)
            service_repo = ServiceRepository(db)
            rules = await known_repo.list_all()
            service = (
                await service_repo.get_by_id(finding.service_id)
                if finding.service_id else None
            )
            matched = first_matching_rule(finding, rules, service)
            if matched:
                finding.status = FindingStatus.SUPPRESSED
                finding.environment_context = f"Auto-suppressed: {matched.reason}"
                await known_repo.record_hit(matched.id)
                Logger.info(
                    "finding.suppressed",
                    extra={"finding_id": finding.id, "rule_id": matched.id},
                )

        # Store finding
        async with get_db() as db:
            finding_repo = FindingRepository(db)
            queue_repo = QueueRepository(db)
            history_repo = HistoryRepository(db)

            await finding_repo.insert(finding)
            await queue_repo.set_completed(queue_item_id)

            status_label = (
                "CONFIRMED EXPLOITABLE"
                if finding.validation_status == ValidationStatus.VALIDATED_EXPLOITABLE
                else "NOT EXPLOITABLE"
            )
            await history_repo.insert(HistoryEntry(
                action=HistoryAction.FINDING,
                summary=f"{status_label} — {finding.finding_type} on port {item.service_id}",
                detail={
                    "finding_id": finding.id,
                    "queue_item_id": queue_item_id,
                    "cve_id": item.cve_id,
                    "validation_status": finding.validation_status,
                    "severity": finding.severity,
                },
            ))

        Logger.info(
            "executor.complete",
            extra={
                "finding_id": finding.id,
                "status": finding.validation_status,
                "severity": finding.severity,
            },
        )

        return finding

    async def execute_many(
        self,
        queue_item_ids: list[str],
        workers: int | None = None,
    ) -> list[Finding | None]:
        """
        Run many approved queue items concurrently, bounded by an
        asyncio.Semaphore(workers). Order of returned findings matches
        the input order; None entries indicate an item that could not
        be executed (missing, not approved, plugin error already logged
        inside execute()).
        """
        if not queue_item_ids:
            return []

        effective = clamp_workers(workers if workers is not None else get_default_workers())
        sem = asyncio.Semaphore(effective)
        Logger.info(
            "executor.execute_many.start",
            extra={"count": len(queue_item_ids), "workers": effective},
        )

        async def _bounded(item_id: str) -> Finding | None:
            async with sem:
                return await self.execute(item_id)

        results = await asyncio.gather(
            *(_bounded(i) for i in queue_item_ids),
            return_exceptions=False,
        )
        Logger.info(
            "executor.execute_many.complete",
            extra={
                "count": len(queue_item_ids),
                "succeeded": sum(1 for r in results if r is not None),
                "workers": effective,
            },
        )
        return list(results)

    async def _run_plugin(self, item: QueueItem) -> Finding:
        """Load and run the appropriate plugin for this queue item."""
        module_path = PLUGIN_REGISTRY.get(item.plugin_name)
        if not module_path:
            raise RuntimeError(f"Unknown plugin: {item.plugin_name}")

        try:
            module = importlib.import_module(module_path)
        except ImportError as e:
            raise RuntimeError(f"Failed to load plugin {item.plugin_name}: {e}") from e

        plugin_fn = getattr(module, "run", None)
        if not plugin_fn:
            raise RuntimeError(f"Plugin {item.plugin_name} missing run() function")

        # Fetch enriched context for the plugin
        async with get_db() as db:
            service_repo = ServiceRepository(db)
            cve_repo = CVERepository(db)

            service = await service_repo.get_by_id(item.service_id)
            cve = await cve_repo.get_by_id(item.cve_id) if item.cve_id else None

        start = time.monotonic()
        evidence: Evidence = await plugin_fn(item, service, cve)
        duration_ms = int((time.monotonic() - start) * 1000)
        evidence.duration_ms = duration_ms

        # Severity precedence: explicit plugin override (non-CVE service checks
        # like Apache misconfig express severity directly) > CVE score >
        # cvss_to_severity(None) which is INFO.
        cvss_score = cve.cvss_score if cve else None
        severity = cvss_to_severity(cvss_score)
        override = evidence.context.get("severity")
        if override:
            try:
                severity = FindingSeverity(str(override).lower())
            except ValueError:
                pass

        return Finding(
            queue_item_id=item.id,
            host_id=item.host_id,
            service_id=item.service_id,
            cve_id=item.cve_id,
            finding_type=item.validation_type,
            cvss_score=cvss_score,
            severity=severity,
            validation_status=evidence.context.get(
                "validation_status", ValidationStatus.CVE_MATCHED
            ),
            evidence=evidence,
            environment_context=evidence.context.get("environment_context"),
            status=FindingStatus.OPEN,
        )
