"""
Scanner service.

Orchestrates the full discovery workflow:
1. Run Nmap adapter
2. Persist hosts and services
3. Detect changes
4. Correlate into queue items
5. Write history entry

This is the only place these four steps are combined.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from uuid import uuid4

from apps.validation.adapters.nmap import NmapAdapter
from apps.validation.database import get_db
from apps.validation.models import HistoryAction, HistoryEntry, ScanRequest, ScanResult
from apps.validation.repositories import HistoryRepository, HostRepository, ServiceRepository
from apps.validation.services.change_detector import ChangeDetector
from apps.validation.services.correlator import Correlator
from sdk import Logger


class ScannerService:
    def __init__(self) -> None:
        self.nmap = NmapAdapter()
        self.change_detector = ChangeDetector()
        self.correlator = Correlator()

    async def run_scan(self, request: ScanRequest) -> ScanResult:
        scan_id = str(uuid4())
        start = time.monotonic()

        Logger.info("scanner.start", extra={"target": request.target, "scan_id": scan_id})

        # Step 1: Run Nmap
        nmap_result = await self.nmap.scan(
            target=request.target,
            scan_type=request.scan_type,
            custom_args=request.custom_args,
            workers=request.workers,
        )

        new_hosts = 0
        new_services = 0

        # Step 2: Persist hosts and services
        async with get_db() as db:
            host_repo = HostRepository(db)
            service_repo = ServiceRepository(db)

            persisted_hosts = []
            for host in nmap_result.hosts:
                existing = await host_repo.get_by_ip(host.ip)
                if existing:
                    persisted_host = existing
                    await host_repo.upsert(host)
                else:
                    persisted_host = await host_repo.upsert(host)
                    new_hosts += 1
                persisted_hosts.append(persisted_host)

            # Remap service host_ids to persisted host ids
            persisted_services = []
            for service in nmap_result.services:
                # Find the persisted host for this service
                orig_host = next(
                    (h for h in nmap_result.hosts if h.id == service.host_id), None
                )
                if orig_host:
                    db_host = await host_repo.get_by_ip(orig_host.ip)
                    if db_host:
                        service.host_id = db_host.id

                svc, is_new = await service_repo.upsert(service)
                if is_new:
                    new_services += 1
                persisted_services.append(svc)

        # Step 3: Detect changes
        known_host_ids = {h.id for h in persisted_hosts}
        changes = await self.change_detector.detect(
            persisted_hosts, persisted_services, known_host_ids
        )

        # Step 4: Correlate into queue items
        queue_items = await self.correlator.correlate(persisted_hosts, persisted_services)

        # Step 5: Write history
        duration_ms = int((time.monotonic() - start) * 1000)
        async with get_db() as db:
            history_repo = HistoryRepository(db)
            await history_repo.insert(HistoryEntry(
                action=HistoryAction.SCAN,
                summary=f"Scanned {request.target} — {len(nmap_result.hosts)} hosts, {len(nmap_result.services)} services",
                detail={
                    "scan_id": scan_id,
                    "target": request.target,
                    "scan_type": request.scan_type,
                    "hosts_found": len(nmap_result.hosts),
                    "services_found": len(nmap_result.services),
                    "new_hosts": new_hosts,
                    "new_services": new_services,
                    "changes": len(changes),
                    "queue_items": len(queue_items),
                    "duration_ms": duration_ms,
                },
            ))

        Logger.info(
            "scanner.complete",
            extra={"scan_id": scan_id, "hosts": len(nmap_result.hosts), "duration_ms": duration_ms},
        )

        return ScanResult(
            scan_id=scan_id,
            target=request.target,
            hosts_found=len(nmap_result.hosts),
            services_found=len(nmap_result.services),
            new_hosts=new_hosts,
            new_services=new_services,
            queue_items_created=len(queue_items),
            duration_ms=duration_ms,
        )

    async def run_scan_stream(self, request: ScanRequest) -> AsyncIterator[dict]:
        """
        Streaming variant of run_scan. Yields progress events as nmap runs,
        then status events as post-processing steps run, then a final
        complete event with the ScanResult.

        Event shapes:
            {"type": "status",   "message": str}
            {"type": "progress", "message": str, "hosts_up": int | None}
            {"type": "complete", "result": ScanResult}
        """
        scan_id = str(uuid4())
        start = time.monotonic()
        Logger.info("scanner.start", extra={"target": request.target, "scan_id": scan_id, "stream": True})

        yield {"type": "status", "message": f"Starting nmap scan of {request.target}…"}

        nmap_result = None
        async for event in self.nmap.scan_stream(
            target=request.target,
            scan_type=request.scan_type,
            custom_args=request.custom_args,
            workers=request.workers,
        ):
            if event["type"] == "progress":
                yield event
            elif event["type"] == "result":
                nmap_result = event["result"]

        if nmap_result is None:
            raise RuntimeError("Nmap stream ended without producing a result")

        yield {
            "type": "status",
            "message": (
                f"Persisting {len(nmap_result.hosts)} host(s) "
                f"and {len(nmap_result.services)} service(s)…"
            ),
        }

        new_hosts = 0
        new_services = 0

        async with get_db() as db:
            host_repo = HostRepository(db)
            service_repo = ServiceRepository(db)

            persisted_hosts = []
            for host in nmap_result.hosts:
                existing = await host_repo.get_by_ip(host.ip)
                if existing:
                    persisted_host = existing
                    await host_repo.upsert(host)
                else:
                    persisted_host = await host_repo.upsert(host)
                    new_hosts += 1
                persisted_hosts.append(persisted_host)

            persisted_services = []
            for service in nmap_result.services:
                orig_host = next(
                    (h for h in nmap_result.hosts if h.id == service.host_id), None
                )
                if orig_host:
                    db_host = await host_repo.get_by_ip(orig_host.ip)
                    if db_host:
                        service.host_id = db_host.id

                svc, is_new = await service_repo.upsert(service)
                if is_new:
                    new_services += 1
                persisted_services.append(svc)

        yield {"type": "status", "message": "Detecting changes…"}
        known_host_ids = {h.id for h in persisted_hosts}
        changes = await self.change_detector.detect(
            persisted_hosts, persisted_services, known_host_ids
        )

        yield {"type": "status", "message": "Correlating CVEs and building queue…"}
        queue_items = await self.correlator.correlate(persisted_hosts, persisted_services)

        duration_ms = int((time.monotonic() - start) * 1000)
        async with get_db() as db:
            history_repo = HistoryRepository(db)
            await history_repo.insert(HistoryEntry(
                action=HistoryAction.SCAN,
                summary=f"Scanned {request.target} — {len(nmap_result.hosts)} hosts, {len(nmap_result.services)} services",
                detail={
                    "scan_id": scan_id,
                    "target": request.target,
                    "scan_type": request.scan_type,
                    "hosts_found": len(nmap_result.hosts),
                    "services_found": len(nmap_result.services),
                    "new_hosts": new_hosts,
                    "new_services": new_services,
                    "changes": len(changes),
                    "queue_items": len(queue_items),
                    "duration_ms": duration_ms,
                },
            ))

        Logger.info(
            "scanner.complete",
            extra={"scan_id": scan_id, "hosts": len(nmap_result.hosts), "duration_ms": duration_ms},
        )

        yield {
            "type": "complete",
            "result": ScanResult(
                scan_id=scan_id,
                target=request.target,
                hosts_found=len(nmap_result.hosts),
                services_found=len(nmap_result.services),
                new_hosts=new_hosts,
                new_services=new_services,
                queue_items_created=len(queue_items),
                duration_ms=duration_ms,
            ),
        }
