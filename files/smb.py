"""SMB enumeration plugin — null session and share enumeration."""
from __future__ import annotations
import asyncio
from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    if not service:
        return Evidence(context={"validation_status": ValidationStatus.CVE_MATCHED})

    host_ip = await _get_host_ip(item.host_id)

    # Use smbclient for null session test
    cmd = ["smbclient", "-L", host_ip, "-N", "--no-pass", "-g"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        output = stdout.decode(errors="replace")
        error = stderr.decode(errors="replace")

        if "Sharename" in output or "IPC$" in output:
            shares = [line for line in output.splitlines() if "|" in line]
            return Evidence(
                sent=f"smbclient -L {host_ip} -N (null session)",
                received=output[:800],
                context={
                    "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE,
                    "environment_context": f"Null SMB session allowed — {len(shares)} shares enumerated without credentials",
                    "shares": shares[:20],
                    "null_session": True,
                },
            )

        return Evidence(
            sent=f"smbclient -L {host_ip} -N (null session)",
            received=error[:400] or "No shares returned",
            context={
                "validation_status": ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
                "environment_context": "Null SMB session rejected — authentication required",
                "null_session": False,
            },
        )
    except FileNotFoundError:
        return Evidence(
            sent=f"smbclient null session test on {host_ip}",
            received="smbclient not available in container",
            context={
                "validation_status": ValidationStatus.CVE_MATCHED,
                "environment_context": "smbclient tool not installed",
            },
        )
    except Exception as e:
        return Evidence(
            sent=f"SMB null session test on {host_ip}",
            received=str(e),
            context={"validation_status": ValidationStatus.CVE_MATCHED,
                     "environment_context": str(e)},
        )


async def _get_host_ip(host_id: str) -> str:
    from apps.validation.database import get_db
    from apps.validation.repositories import HostRepository
    async with await get_db() as db:
        repo = HostRepository(db)
        host = await repo.get_by_id(host_id)
    return host.ip if host else "unknown"
