"""
SMB enumeration plugin.

Two layers, in order of preference:

1. **impacket null-session enumeration** — when impacket is importable,
   the plugin opens an `SMBConnection` (via `asyncio.to_thread`), attempts
   an anonymous login, and enumerates available shares. This is the
   authentic null-session test.

2. **Pure-Python TCP + SMB2 NEGOTIATE probe** — if impacket isn't
   available, fall back to opening port 445 (or 139) with
   `asyncio.open_connection`, sending an SMB2 NEGOTIATE_PROTOCOL packet
   and parsing the response header for the `\\xFESMB` / `\\xFFSMB`
   dialect marker. This proves the port speaks SMB without attempting
   any authentication.

Validation status:
- VALIDATED_EXPLOITABLE → impacket null session succeeded and shares
  were listed (or IPC$ visible)
- VALIDATED_NOT_EXPLOITABLE → port unreachable, OR impacket null
  session was rejected
- CVE_MATCHED → port is reachable but no real null-session test was
  possible (impacket missing); honest evidence with limitation noted
"""

from __future__ import annotations

import asyncio

from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus
from sdk import Logger

_PROBE_TIMEOUT = 5.0
_SMB_TIMEOUT = 8.0
_GREETING_MAX = 512

# SMB2 NEGOTIATE_PROTOCOL request — single dialect (SMB 2.0.2).
_SMB2_NEGOTIATE = bytes.fromhex(
    "000000a4"
    "fe534d4240000100000000000000010000000000000000000000000000000000"
    "fffe000000000000000000000000000000000000000000000000000000000000"
    "240001000000000000000000000000000000000078000000020000000202100200"
    "0300020003020311030000000100260000000000010020000100" + "00" * 32 +
    "00000200060000000000020001000200"
)

try:
    from impacket.smbconnection import SMBConnection  # type: ignore[import-untyped]
    from impacket.smbconnection import SessionError  # type: ignore[import-untyped]

    _IMPACKET_AVAILABLE = True
    _IMPACKET_IMPORT_ERROR: str | None = None
except Exception as _e:  # pragma: no cover — import-time guard
    SMBConnection = None  # type: ignore[assignment]
    SessionError = Exception  # type: ignore[assignment]
    _IMPACKET_AVAILABLE = False
    _IMPACKET_IMPORT_ERROR = str(_e)
    Logger.info("smb.impacket.unavailable", extra={"error": _IMPACKET_IMPORT_ERROR})


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    if not service:
        return Evidence(context={"validation_status": ValidationStatus.CVE_MATCHED})

    host_ip = await _get_host_ip(item.host_id)
    port = service.port if service.port in (445, 139) else 445

    if _IMPACKET_AVAILABLE:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_impacket_null_session_sync, host_ip, port),
                timeout=_SMB_TIMEOUT + 4,
            )
        except TimeoutError:
            return Evidence(
                sent=f"impacket SMBConnection null-session to {host_ip}:{port}",
                received="Timed out before completing the null-session test",
                context={
                    "validation_status": ValidationStatus.CVE_MATCHED,
                    "environment_context": "SMB null session test timed out",
                    "tool_available": True,
                    "tool_reason": "impacket present but the session timed out",
                },
            )
        except Exception as e:
            # Fall through to the TCP-probe fallback rather than failing hard.
            Logger.info("smb.impacket.error_falling_back", extra={"error": str(e)})

    return await _tcp_probe_evidence(host_ip, port)


# ---------------------------------------------------------------------------
# Layer 1 — impacket null session (sync, wrapped via asyncio.to_thread)
# ---------------------------------------------------------------------------


def _impacket_null_session_sync(host: str, port: int) -> Evidence:
    """
    Attempt an anonymous (null) login against host:port and list the
    available shares. Returns an Evidence summarising the outcome.
    """
    assert SMBConnection is not None  # narrowing
    try:
        conn = SMBConnection(remoteName=host, remoteHost=host, sess_port=port, timeout=_SMB_TIMEOUT)
    except Exception as e:
        return Evidence(
            sent=f"impacket SMBConnection({host}:{port})",
            received=f"Could not establish SMB transport: {e}",
            context={
                "validation_status": ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
                "environment_context": f"SMB port {port} not reachable on {host}: {e}",
                "tool_available": True,
            },
        )

    try:
        try:
            conn.login("", "")  # anonymous / null session
        except SessionError as e:
            return Evidence(
                sent=f"impacket null-session login to {host}:{port}",
                received=f"Login rejected: {e}",
                context={
                    "validation_status": ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
                    "environment_context": (
                        "Null SMB session rejected — server requires authentication."
                    ),
                    "null_session": False,
                    "tool_available": True,
                },
            )
        except Exception as e:
            return Evidence(
                sent=f"impacket null-session login to {host}:{port}",
                received=f"Login error: {e}",
                context={
                    "validation_status": ValidationStatus.CVE_MATCHED,
                    "environment_context": f"SMB login attempt errored: {e}",
                    "tool_available": True,
                },
            )

        try:
            shares_resp = conn.listShares()
        except Exception as e:
            return Evidence(
                sent=f"impacket null-session listShares on {host}:{port}",
                received=f"Null session opened but listShares failed: {e}",
                context={
                    "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE,
                    "environment_context": (
                        "Null session accepted — share enumeration failed but the "
                        "anonymous authentication succeeded."
                    ),
                    "null_session": True,
                    "share_listing_error": str(e),
                    "tool_available": True,
                },
            )

        shares = []
        for s in shares_resp:
            try:
                name = s["shi1_netname"][:-1] if s["shi1_netname"].endswith("\x00") else s["shi1_netname"]
            except Exception:
                name = repr(s)[:80]
            shares.append(str(name))

        server_os = None
        try:
            server_os = conn.getServerOS()
        except Exception:
            pass

        return Evidence(
            sent=f"impacket null-session enumeration of {host}:{port}",
            received=f"Shares: {', '.join(shares) or '(none)'} | server_os={server_os}",
            context={
                "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE,
                "environment_context": (
                    f"Null SMB session allowed — {len(shares)} share(s) enumerated "
                    "without credentials."
                ),
                "null_session": True,
                "shares": shares[:50],
                "server_os": server_os,
                "tool_available": True,
            },
        )
    finally:
        try:
            conn.logoff()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Layer 2 — TCP+SMB2 probe (used when impacket is unavailable or errored)
# ---------------------------------------------------------------------------


async def _tcp_probe_evidence(host_ip: str, port: int) -> Evidence:
    probe = await _probe_smb(host_ip, port)
    if probe["reachable"] is False:
        return Evidence(
            sent=f"TCP connect to {host_ip}:{port}",
            received=probe.get("error") or "Connection refused / unreachable",
            context={
                "validation_status": ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
                "environment_context": f"SMB port {port} not reachable on {host_ip}",
                "tool_available": False,
                "tool_reason": (
                    f"impacket not available ({_IMPACKET_IMPORT_ERROR}) — "
                    "fell back to TCP reachability probe."
                ),
            },
        )

    dialect_marker = probe.get("smb_version")
    greeting_hex = probe.get("greeting_hex")

    return Evidence(
        sent=(
            f"TCP connect to {host_ip}:{port} + SMB2 NEGOTIATE_PROTOCOL probe "
            "(reachability only — null-session enumeration requires impacket)"
        ),
        received=(
            f"Reachable; greeting={greeting_hex[:80] if greeting_hex else 'none'} "
            f"dialect_marker={dialect_marker or 'not detected'}"
        ),
        context={
            "validation_status": ValidationStatus.CVE_MATCHED,
            "environment_context": (
                f"SMB port {port} reachable on {host_ip}; full null-session "
                "enumeration unavailable in this environment."
            ),
            "reachable": True,
            "smb_version_marker": dialect_marker,
            "greeting_hex_preview": greeting_hex[:160] if greeting_hex else None,
            "tool_available": False,
            "tool_reason": (
                f"impacket import failed: {_IMPACKET_IMPORT_ERROR}"
            ),
        },
    )


async def _probe_smb(host: str, port: int) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_PROBE_TIMEOUT
        )
    except (TimeoutError, OSError) as e:
        return {"reachable": False, "error": f"{type(e).__name__}: {e}"}

    try:
        try:
            writer.write(_SMB2_NEGOTIATE)
            await asyncio.wait_for(writer.drain(), timeout=_PROBE_TIMEOUT)
            data = await asyncio.wait_for(reader.read(_GREETING_MAX), timeout=_PROBE_TIMEOUT)
        except (TimeoutError, OSError) as e:
            return {"reachable": True, "error": f"{type(e).__name__}: {e}"}

        if not data:
            return {"reachable": True, "greeting_hex": None, "smb_version": None}

        marker = None
        if len(data) >= 8 and data[4:8] == b"\xfeSMB":
            marker = "SMB2/3"
        elif len(data) >= 8 and data[4:8] == b"\xffSMB":
            marker = "SMB1"
        return {
            "reachable": True,
            "smb_version": marker,
            "greeting_hex": data[:64].hex(),
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
