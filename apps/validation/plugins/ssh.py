"""
SSH validation plugin.

Two layers, in order of preference:

1. **paramiko credential validation** — when paramiko is importable, the
   plugin uses it (via asyncio.to_thread) to attempt each credential pair
   from the configured wordlist. Concurrent attempts are bounded by
   `asyncio.Semaphore(workers)`; the first success short-circuits the
   rest. Single controlled attempt per pair — never loops.

2. **Pure-Python banner read** — if paramiko isn't available, fall back
   to a TCP banner-grab via `asyncio.open_connection`. This works as
   a non-root user, with no extra system binaries, and produces honest
   evidence stating that credential validation was not performed.

Validation status:
- VALIDATED_EXPLOITABLE → paramiko accepted a credential pair
- VALIDATED_NOT_EXPLOITABLE → paramiko rejected every pair AND we
  actually attempted credentials (i.e. paramiko is installed)
- CVE_MATCHED → no credential test ran (paramiko missing or no
  wordlist loaded); banner-only evidence collected
"""

from __future__ import annotations

import asyncio

from apps.validation.config import get_default_workers
from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus
from sdk import Logger

_BANNER_TIMEOUT = 5.0
_BANNER_MAX = 512
_AUTH_TIMEOUT = 6.0

try:
    import paramiko  # type: ignore[import-untyped]

    _PARAMIKO_AVAILABLE = True
    _PARAMIKO_IMPORT_ERROR: str | None = None
except Exception as _e:  # pragma: no cover — import-time guard
    paramiko = None  # type: ignore[assignment]
    _PARAMIKO_AVAILABLE = False
    _PARAMIKO_IMPORT_ERROR = str(_e)
    Logger.info("ssh.paramiko.unavailable", extra={"error": _PARAMIKO_IMPORT_ERROR})


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    if not service:
        return Evidence(context={
            "validation_status": ValidationStatus.CVE_MATCHED,
            "environment_context": "Service not found in database",
        })

    host_ip = await _get_host_ip(item.host_id)
    port = service.port

    banner = await _read_ssh_banner(host_ip, port)
    creds = _load_credentials()
    workers = get_default_workers()

    if banner is None and not _PARAMIKO_AVAILABLE:
        return Evidence(
            sent=f"TCP connect to {host_ip}:{port}",
            received="Connection failed or no SSH banner received within timeout",
            context={
                "validation_status": ValidationStatus.CVE_MATCHED,
                "environment_context": (
                    "Could not retrieve SSH identification banner — service may be "
                    "filtered, slow to respond, or not actually SSH."
                ),
                "credentials_configured": len(creds),
                "credential_test_available": False,
            },
        )

    banner_summary = _parse_banner(banner) if banner else {}

    # No credential validation possible — return banner-only evidence.
    if not _PARAMIKO_AVAILABLE or not creds:
        reason = (
            f"paramiko not installed ({_PARAMIKO_IMPORT_ERROR})"
            if not _PARAMIKO_AVAILABLE
            else "no credentials configured (ssh_credentials_default wordlist empty or missing)"
        )
        return Evidence(
            sent=f"TCP connect to {host_ip}:{port} and read SSH identification banner",
            received=banner or "No banner received",
            context={
                "validation_status": ValidationStatus.CVE_MATCHED,
                "environment_context": (
                    f"SSH banner observed; credential validation skipped: {reason}"
                ),
                "banner": banner,
                **banner_summary,
                "credentials_configured": len(creds),
                "credential_test_available": False,
                "credential_test_reason": reason,
            },
        )

    # Run paramiko credential attempts concurrently, bounded by Semaphore,
    # short-circuit on first success.
    hit = await _try_credentials_with_paramiko(host_ip, port, creds, workers)
    if hit is not None:
        username, password, banner_from_session = hit
        return Evidence(
            sent=f"paramiko SSH connect {username}@{host_ip}:{port} (single attempt)",
            received=(
                f"Authentication succeeded — banner: "
                f"{banner_from_session or banner or 'unavailable'}"
            ),
            context={
                "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE,
                "environment_context": (
                    f"Default credential {username}/{password} accepted by SSH server"
                ),
                "username": username,
                "password": password,
                "banner": banner_from_session or banner,
                **banner_summary,
                "credentials_configured": len(creds),
                "credential_test_available": True,
            },
        )

    return Evidence(
        sent=f"paramiko SSH credential test against {host_ip}:{port} "
             f"({len(creds)} pairs, workers={workers})",
        received="All credential attempts rejected by SSH server",
        context={
            "validation_status": ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
            "environment_context": (
                f"Tested {len(creds)} default credential pairs via paramiko — none accepted."
            ),
            "banner": banner,
            **banner_summary,
            "attempts": len(creds),
            "workers": workers,
            "credentials_configured": len(creds),
            "credential_test_available": True,
        },
    )


# ---------------------------------------------------------------------------
# Banner read — works without paramiko, without root
# ---------------------------------------------------------------------------


async def _read_ssh_banner(host: str, port: int) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_BANNER_TIMEOUT
        )
    except (TimeoutError, OSError):
        return None

    try:
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=_BANNER_TIMEOUT)
        except (TimeoutError, asyncio.IncompleteReadError):
            return None
        if not raw:
            return None
        text = raw[:_BANNER_MAX].decode(errors="replace").rstrip("\r\n")
        return text or None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _parse_banner(banner: str) -> dict:
    """Pull protocol_version + software fields out of an SSH identification string."""
    parts = banner.split("-", 2)
    if len(parts) < 3:
        return {"protocol_version": None, "software": banner}
    return {"protocol_version": parts[1], "software": parts[2].strip()}


# ---------------------------------------------------------------------------
# paramiko credential testing — sync, wrapped via asyncio.to_thread
# ---------------------------------------------------------------------------


def _paramiko_attempt_sync(host: str, port: int, username: str, password: str) -> dict:
    """
    One controlled paramiko connect attempt. Returns a dict with:
        success: bool
        rejected: bool   (auth failed — server is up, creds wrong)
        error: str | None (transport / network error)
        banner: str | None
    """
    assert paramiko is not None  # narrowing for type checkers
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=_AUTH_TIMEOUT,
            banner_timeout=_AUTH_TIMEOUT,
            auth_timeout=_AUTH_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        transport = client.get_transport()
        banner = transport.get_banner() if transport else None
        if isinstance(banner, bytes):
            banner = banner.decode(errors="replace")
        return {"success": True, "rejected": False, "error": None, "banner": banner}
    except paramiko.AuthenticationException as e:
        return {"success": False, "rejected": True, "error": str(e), "banner": None}
    except (paramiko.SSHException, TimeoutError, OSError) as e:
        return {"success": False, "rejected": False, "error": f"{type(e).__name__}: {e}",
                "banner": None}
    finally:
        try:
            client.close()
        except Exception:
            pass


async def _try_credentials_with_paramiko(
    host: str,
    port: int,
    creds: list[tuple[str, str]],
    workers: int,
) -> tuple[str, str, str | None] | None:
    """
    Fire all credential attempts concurrently bounded by Semaphore(workers).
    Returns (username, password, banner) on first success, None otherwise.
    Cancels in-flight attempts when a winner is found.
    """
    sem = asyncio.Semaphore(max(1, workers))

    async def attempt(u: str, p: str) -> tuple[str, str, dict]:
        async with sem:
            res = await asyncio.to_thread(_paramiko_attempt_sync, host, port, u, p)
            return u, p, res

    tasks = [asyncio.create_task(attempt(u, p)) for u, p in creds]
    try:
        for fut in asyncio.as_completed(tasks):
            u, p, res = await fut
            if res.get("success"):
                return u, p, res.get("banner")
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return None


# ---------------------------------------------------------------------------
# Wordlist + host lookup
# ---------------------------------------------------------------------------


def _load_credentials() -> list[tuple[str, str]]:
    from apps.conductor.wordlists import WordlistFileNotFoundError, load_entries
    try:
        entries = load_entries("ssh_credentials_default")
    except WordlistFileNotFoundError:
        return []
    return [(e["username"], e["password"]) for e in entries]


async def _get_host_ip(host_id: str) -> str:
    from apps.validation.database import get_db
    from apps.validation.repositories import HostRepository
    async with get_db() as db:
        repo = HostRepository(db)
        host = await repo.get_by_id(host_id)
    return host.ip if host else "unknown"
