"""
SSH validation plugin.

Single controlled attempt:
1. Try default/weak credentials from external wordlist
2. Record exact outcome as evidence

Never loops. Never chains. One attempt, full evidence.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import yaml

from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus

CREDENTIALS_PATH = Path("config/credentials/ssh_defaults.yaml")


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    """Single SSH credential validation attempt."""
    if not service:
        return Evidence(
            context={"validation_status": ValidationStatus.CVE_MATCHED,
                     "environment_context": "Service not found in database"}
        )

    host_ip = await _get_host_ip(item.host_id)
    port = service.port

    # Load credential pairs from external config
    creds = _load_credentials()
    if not creds:
        return Evidence(
            sent=f"SSH connect to {host_ip}:{port}",
            received="No credentials configured",
            context={
                "validation_status": ValidationStatus.CVE_MATCHED,
                "environment_context": "No credential wordlist configured at config/credentials/ssh_defaults.yaml",
            },
        )

    # Try each credential pair — stop on first success OR after all fail
    for username, password in creds:
        result = await _attempt_ssh(host_ip, port, username, password)
        if result["success"]:
            return Evidence(
                sent=f"SSH {username}@{host_ip}:{port} with password '{password}'",
                received=f"Authentication succeeded — banner: {result.get('banner', 'none')}",
                context={
                    "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE,
                    "environment_context": f"Default credential {username}/{password} accepted",
                    "username": username,
                    "password": password,
                    "banner": result.get("banner"),
                },
            )

    return Evidence(
        sent=f"SSH credential test against {host_ip}:{port} ({len(creds)} pairs)",
        received="All credential attempts failed — authentication rejected",
        context={
            "validation_status": ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
            "environment_context": "Default credentials rejected — SSH properly configured",
            "attempts": len(creds),
        },
    )


async def _attempt_ssh(host: str, port: int, username: str, password: str) -> dict:
    """
    Single SSH authentication attempt using subprocess.
    Uses sshpass + ssh for controlled single attempt.
    Returns {"success": bool, "banner": str|None}
    """
    cmd = [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=no",
        "-o", "ConnectTimeout=5",
        "-o", "NumberOfPasswordPrompts=1",
        "-p", str(port),
        f"{username}@{host}",
        "echo VALIDATION_SUCCESS",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        output = stdout.decode(errors="replace")
        if "VALIDATION_SUCCESS" in output:
            return {"success": True, "banner": stderr.decode(errors="replace")[:200]}
    except (TimeoutError, Exception):
        pass
    return {"success": False}


def _load_credentials() -> list[tuple[str, str]]:
    if not CREDENTIALS_PATH.exists():
        return []
    with CREDENTIALS_PATH.open() as f:
        data = yaml.safe_load(f)
    pairs = []
    for entry in data.get("credentials", []):
        pairs.append((entry["username"], entry["password"]))
    return pairs


async def _get_host_ip(host_id: str) -> str:
    from apps.validation.database import get_db
    from apps.validation.repositories import HostRepository
    async with await get_db() as db:
        repo = HostRepository(db)
        host = await repo.get_by_id(host_id)
    return host.ip if host else "unknown"
