"""SQLi detection plugin — single test payload, no fuzzing."""
from __future__ import annotations
import asyncio
import httpx
from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus

# Single safe detection payload — causes delay on vulnerable systems
SQLI_TIME_PAYLOAD = "' OR SLEEP(3)-- "
SQLI_ERROR_PAYLOAD = "'"


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    if not service:
        return Evidence(context={"validation_status": ValidationStatus.CVE_MATCHED})

    host_ip = await _get_host_ip(item.host_id)
    port = service.port
    service_name = (service.service_name or "").lower()

    # Web-exposed database — check via HTTP
    if port in (80, 443, 8080, 8443):
        return await _check_web_sqli(host_ip, port)

    # Direct DB port — check if anonymous login possible
    return await _check_db_port(host_ip, port, service_name)


async def _check_web_sqli(host: str, port: int) -> Evidence:
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{host}:{port}"

    test_url = f"{base}/?id={SQLI_ERROR_PAYLOAD}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.get(test_url)
            body = resp.text[:1000]

        error_signatures = [
            "SQL syntax", "mysql_fetch", "ORA-", "SQLite3::",
            "Warning: pg_", "Unclosed quotation", "ODBC SQL",
        ]
        errors_found = [sig for sig in error_signatures if sig in body]

        if errors_found:
            return Evidence(
                sent=f"GET {test_url}",
                received=f"SQL error in response: {', '.join(errors_found)}",
                context={
                    "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE,
                    "environment_context": f"SQL error messages exposed — {', '.join(errors_found)}",
                    "error_signatures": errors_found,
                },
            )

        return Evidence(
            sent=f"GET {test_url}",
            received=f"Status {resp.status_code} — no SQL errors in response",
            context={
                "validation_status": ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
                "environment_context": "No SQL error messages exposed to single quote injection",
            },
        )
    except Exception as e:
        return Evidence(
            sent=f"SQLi test on {test_url}",
            received=str(e),
            context={"validation_status": ValidationStatus.CVE_MATCHED,
                     "environment_context": str(e)},
        )


async def _check_db_port(host: str, port: int, service_name: str) -> Evidence:
    """Check if DB port accepts anonymous/no-auth connection."""
    cmd_map = {
        3306: ["mysql", "-h", host, "-P", str(port), "--connect-timeout=5", "-u", "root", "--password=", "-e", "SELECT VERSION();"],
        5432: ["psql", f"postgresql://postgres@{host}:{port}/postgres", "-c", "SELECT version();", "--no-password"],
        1433: ["sqlcmd", "-S", f"{host},{port}", "-Q", "SELECT @@VERSION", "-l", "5"],
    }
    cmd = cmd_map.get(port)
    if not cmd:
        return Evidence(
            sent=f"DB port check on {host}:{port}",
            received="No anonymous check available for this DB type",
            context={"validation_status": ValidationStatus.CVE_MATCHED,
                     "environment_context": "No check implemented for this database port"},
        )

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        output = stdout.decode(errors="replace")
        error = stderr.decode(errors="replace")

        if any(x in output for x in ("version", "VERSION", "Microsoft SQL")):
            return Evidence(
                sent=" ".join(cmd[:4]) + " ...",
                received=output[:400],
                context={
                    "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE,
                    "environment_context": "Database accessible without credentials",
                },
            )

        return Evidence(
            sent=" ".join(cmd[:4]) + " ...",
            received=error[:400] or "Access denied",
            context={
                "validation_status": ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
                "environment_context": "Database requires authentication",
            },
        )
    except Exception as e:
        return Evidence(
            sent=f"DB auth test {host}:{port}",
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
