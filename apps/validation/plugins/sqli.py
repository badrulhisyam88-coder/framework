"""SQLi detection plugin — single test payload, no fuzzing."""
from __future__ import annotations

import asyncio

import httpx

from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus

# Single safe detection payload — single quote breaks naive query construction.
SQLI_ERROR_PAYLOAD = "'"

_DB_GREETING_TIMEOUT = 5.0
_GREETING_MAX = 256


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    if not service:
        return Evidence(context={"validation_status": ValidationStatus.CVE_MATCHED})

    host_ip = await _get_host_ip(item.host_id)
    port = service.port

    # Web-exposed database — check via HTTP
    if port in (80, 443, 8080, 8443):
        return await _check_web_sqli(host_ip, port)

    # Direct DB port — banner-only reachability probe (CLI clients not installed)
    return await _check_db_port(host_ip, port, (service.service_name or "").lower())


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
    """
    Direct-DB port probe.

    Container reality: mysql / psql / sqlcmd are not installed, and we
    run as non-root. So we replace the CLI auth attempt with an
    application-layer reachability check — open the port and read up
    to 256 bytes of greeting. PostgreSQL and MS-SQL both stay silent
    until the client speaks first, but MySQL/MariaDB send a handshake
    packet on connect that includes a server-version string we can
    detect without a DB driver.
    """
    db_label = _DB_LABELS.get(port, service_name or f"unknown-port-{port}")

    probe = await _probe_db_port(host, port)
    if not probe["reachable"]:
        return Evidence(
            sent=f"TCP connect to {host}:{port}",
            received=probe.get("error") or "Connection refused / unreachable",
            context={
                "validation_status": ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
                "environment_context": f"{db_label} port not reachable on {host}",
                "tool_available": False,
                "tool_reason": (
                    "Direct DB auth probes need a matching CLI client "
                    "(mysql/psql/sqlcmd) — none installed in this container."
                ),
            },
        )

    greeting_hex = probe.get("greeting_hex")
    detected = probe.get("server_hint")

    return Evidence(
        sent=(
            f"TCP connect to {host}:{port} ({db_label}) and read up to "
            f"{_GREETING_MAX} bytes of server greeting"
        ),
        received=(
            f"Reachable; server_hint={detected or 'silent (waits for client handshake)'} "
            f"greeting={greeting_hex[:80] if greeting_hex else 'none'}"
        ),
        context={
            "validation_status": ValidationStatus.CVE_MATCHED,
            "environment_context": (
                f"{db_label} port reachable on {host}:{port}; authenticated SQL probe "
                "skipped because no DB client (mysql/psql/sqlcmd) is installed."
            ),
            "reachable": True,
            "server_hint": detected,
            "greeting_hex_preview": greeting_hex[:160] if greeting_hex else None,
            "tool_available": False,
            "tool_reason": (
                "Install mariadb-client / postgresql-client / mssql-tools to enable "
                "authenticated database checks."
            ),
        },
    )


_DB_LABELS = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    1433: "MS SQL Server",
    1521: "Oracle TNS Listener",
}


async def _probe_db_port(host: str, port: int) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_DB_GREETING_TIMEOUT
        )
    except (TimeoutError, OSError) as e:
        return {"reachable": False, "error": f"{type(e).__name__}: {e}"}

    try:
        try:
            data = await asyncio.wait_for(reader.read(_GREETING_MAX), timeout=2.0)
        except (TimeoutError, OSError):
            data = b""

        hint = None
        if data:
            # MySQL/MariaDB: 4-byte packet header, payload byte 0 = protocol version
            # (usually 0x0a), followed by a NUL-terminated server-version string.
            if len(data) >= 6 and data[4] in (0x09, 0x0a):
                try:
                    end = data.index(b"\x00", 5)
                    version = data[5:end].decode(errors="replace")
                    hint = f"mysql/mariadb server_version='{version}'"
                except ValueError:
                    hint = "mysql/mariadb-shaped handshake (no NUL-terminated version)"
            elif b"PostgreSQL" in data or b"postgres" in data:
                hint = "postgres-style banner observed"

        return {
            "reachable": True,
            "server_hint": hint,
            "greeting_hex": data[:64].hex() if data else None,
        }
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _get_host_ip(host_id: str) -> str:
    from apps.validation.database import get_db
    from apps.validation.repositories import HostRepository
    async with get_db() as db:
        repo = HostRepository(db)
        host = await repo.get_by_id(host_id)
    return host.ip if host else "unknown"
