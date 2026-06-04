"""
Executor service.

Runs approved queue items through the appropriate plugin.
Single controlled attempt. Records evidence. Stores finding.

This is the only place plugins are invoked.
Nothing runs without queue_item.status == 'approved'.
"""

from __future__ import annotations

import importlib
import time

from apps.validation.database import get_db
from apps.validation.models import (
    Evidence,
    Finding,
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
    QueueRepository,
    ServiceRepository,
)
from sdk import Logger

# Plugin registry — maps plugin_name to module path
PLUGIN_REGISTRY = {
    "ssh_plugin": "apps.validation.plugins.ssh",
    "web_plugin": "apps.validation.plugins.web",
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
        async with await get_db() as db:
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
        async with await get_db() as db:
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
            async with await get_db() as db:
                queue_repo = QueueRepository(db)
                await queue_repo.set_failed(queue_item_id, str(e)[:500])
            return None

        # Store finding
        async with await get_db() as db:
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
        async with await get_db() as db:
            service_repo = ServiceRepository(db)
            cve_repo = CVERepository(db)

            service = await service_repo.get_by_id(item.service_id)
            cve = await cve_repo.get_by_id(item.cve_id) if item.cve_id else None

        start = time.monotonic()
        evidence: Evidence = await plugin_fn(item, service, cve)
        duration_ms = int((time.monotonic() - start) * 1000)
        evidence.duration_ms = duration_ms

        # Determine finding severity from CVE score or plugin-set default
        cvss_score = cve.cvss_score if cve else None
        severity = cvss_to_severity(cvss_score)

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
