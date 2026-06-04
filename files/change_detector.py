"""
Change detector service.

Compares newly discovered hosts/services against what's already
in the database and records differences.

Change types:
- new_host       : IP never seen before
- new_service    : port/protocol never seen on this host
- service_changed: version or banner changed since last scan
- host_gone      : host was active, not seen in latest scan
"""

from __future__ import annotations

from apps.validation.database import get_db
from apps.validation.models import Change, ChangeType, Host, Service
from apps.validation.repositories import ChangeRepository, HostRepository, ServiceRepository
from sdk import Logger


class ChangeDetector:
    async def detect(
        self,
        scanned_hosts: list[Host],
        scanned_services: list[Service],
        known_host_ids: set[str],
    ) -> list[Change]:
        """
        Compare scan results against existing database records.
        Returns list of detected changes (already persisted).
        """
        changes: list[Change] = []

        async with await get_db() as db:
            host_repo = HostRepository(db)
            service_repo = ServiceRepository(db)
            change_repo = ChangeRepository(db)

            scanned_ips = {h.ip for h in scanned_hosts}

            for host in scanned_hosts:
                existing = await host_repo.get_by_ip(host.ip)
                if not existing:
                    change = Change(
                        host_id=host.id,
                        change_type=ChangeType.NEW_HOST,
                        detail={"ip": host.ip, "hostname": host.hostname, "os_guess": host.os_guess},
                    )
                    await change_repo.insert(change)
                    changes.append(change)
                    Logger.info("change.new_host", extra={"ip": host.ip})

            for service in scanned_services:
                existing = await service_repo.get_by_host_port(
                    service.host_id, service.port, service.protocol
                )
                if not existing:
                    change = Change(
                        host_id=service.host_id,
                        service_id=service.id,
                        change_type=ChangeType.NEW_SERVICE,
                        detail={
                            "port": service.port,
                            "protocol": service.protocol,
                            "service_name": service.service_name,
                            "product": service.product,
                            "version": service.version,
                        },
                    )
                    await change_repo.insert(change)
                    changes.append(change)
                    Logger.info(
                        "change.new_service",
                        extra={"port": service.port, "service": service.service_name},
                    )
                elif _service_changed(existing, service):
                    change = Change(
                        host_id=service.host_id,
                        service_id=existing.id,
                        change_type=ChangeType.SERVICE_CHANGED,
                        detail={
                            "port": service.port,
                            "old_version": existing.version,
                            "new_version": service.version,
                            "old_banner": existing.banner,
                            "new_banner": service.banner,
                        },
                    )
                    await change_repo.insert(change)
                    changes.append(change)
                    Logger.info(
                        "change.service_changed",
                        extra={"port": service.port, "old": existing.version, "new": service.version},
                    )

        Logger.info("change_detector.complete", extra={"changes": len(changes)})
        return changes


def _service_changed(old: Service, new: Service) -> bool:
    return old.version != new.version or old.banner != new.banner
