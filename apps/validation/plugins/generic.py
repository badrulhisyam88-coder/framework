"""Generic fallback plugin — used when no specific plugin matches."""
from __future__ import annotations
from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    return Evidence(
        sent=f"Generic check for {item.validation_type} on port {service.port if service else 'unknown'}",
        received="No specific plugin available for this service type",
        context={
            "validation_status": ValidationStatus.CVE_MATCHED,
            "environment_context": "Manual investigation required — no automated check available for this service",
            "cve_id": item.cve_id,
            "plugin": item.plugin_name,
        },
    )
