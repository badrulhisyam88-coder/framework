"""Telnet cleartext credential capture plugin."""
from __future__ import annotations
import asyncio
from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    if not service:
        return Evidence(context={"validation_status": ValidationStatus.CVE_MATCHED})

    host_ip = await _get_host_ip(item.host_id)
    port = service.port

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host_ip, port), timeout=5
        )
        banner = await asyncio.wait_for(reader.read(1024), timeout=3)
        banner_text = banner.decode(errors="replace").strip()

        # Send a test username to observe cleartext transmission
        writer.write(b"testuser\r\n")
        await asyncio.wait_for(writer.drain(), timeout=3)
        response = await asyncio.wait_for(reader.read(512), timeout=3)
        response_text = response.decode(errors="replace").strip()
        writer.close()

        return Evidence(
            sent=f"Telnet connect to {host_ip}:{port} — sent plaintext username",
            received=f"Banner: {banner_text[:200]} | Response: {response_text[:200]}",
            context={
                "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE,
                "environment_context": "Telnet transmits credentials in cleartext — protocol is inherently insecure",
                "banner": banner_text[:200],
                "cleartext_observed": True,
            },
        )
    except Exception as e:
        return Evidence(
            sent=f"Telnet connect to {host_ip}:{port}",
            received=f"Connection failed: {e}",
            context={
                "validation_status": ValidationStatus.CVE_MATCHED,
                "environment_context": f"Telnet port open but connection failed: {e}",
            },
        )


async def _get_host_ip(host_id: str) -> str:
    from apps.validation.database import get_db
    from apps.validation.repositories import HostRepository
    async with get_db() as db:
        repo = HostRepository(db)
        host = await repo.get_by_id(host_id)
    return host.ip if host else "unknown"
