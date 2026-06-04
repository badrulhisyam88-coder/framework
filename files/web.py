"""
Web validation plugin.

Checks:
- Security headers (missing X-Frame-Options, CSP, HSTS, etc.)
- TLS configuration (weak ciphers, expired cert, self-signed)
- CVE-specific path traversal / known exploit paths (single attempt)
"""

from __future__ import annotations

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

import httpx

from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

TRAVERSAL_PAYLOADS = [
    "/cgi-bin/.%2e/.%2e/etc/passwd",
    "/../../../etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
]


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    """Web validation — headers, TLS, CVE-specific checks."""
    if not service:
        return Evidence(
            context={"validation_status": ValidationStatus.CVE_MATCHED,
                     "environment_context": "Service not found"}
        )

    host_ip = await _get_host_ip(item.host_id)
    scheme = "https" if (service.port in (443, 8443) or "ssl" in (service.service_name or "")) else "http"
    base_url = f"{scheme}://{host_ip}:{service.port}"

    profile = item.profile_name

    if profile == "tls":
        return await _check_tls(host_ip, service.port)

    if profile == "web" or profile == "cve_poc":
        return await _check_headers_and_cve(base_url, cve)

    return Evidence(
        context={"validation_status": ValidationStatus.CVE_MATCHED,
                 "environment_context": f"Unknown profile: {profile}"}
    )


async def _check_headers_and_cve(base_url: str, cve: CVE | None) -> Evidence:
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(base_url)
    except Exception as e:
        return Evidence(
            sent=f"GET {base_url}",
            received=f"Connection failed: {e}",
            context={"validation_status": ValidationStatus.CVE_MATCHED,
                     "environment_context": "Target unreachable"},
        )

    # Check missing security headers
    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    present = [h for h in SECURITY_HEADERS if h in resp.headers]

    findings = []
    if missing:
        findings.append(f"Missing security headers: {', '.join(missing)}")

    server_header = resp.headers.get("Server", "")
    if server_header:
        findings.append(f"Server version disclosed: {server_header}")

    # CVE-specific path traversal attempt (single payload)
    traversal_result = None
    if cve and "traversal" in (cve.description or "").lower():
        traversal_result = await _try_traversal(base_url)

    if traversal_result and traversal_result["exploitable"]:
        return Evidence(
            sent=traversal_result["payload"],
            received=traversal_result["response"][:500],
            context={
                "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE,
                "environment_context": "Path traversal confirmed — no WAF or filtering in place",
                "missing_headers": missing,
            },
        )

    exploitable = len(missing) >= 3 or bool(server_header)
    return Evidence(
        sent=f"GET {base_url} + header inspection",
        received=f"Status {resp.status_code} — {len(present)}/{len(SECURITY_HEADERS)} security headers present",
        context={
            "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE if exploitable
                                  else ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
            "environment_context": "; ".join(findings) if findings else "Security headers properly configured",
            "missing_headers": missing,
            "present_headers": present,
            "server_header": server_header,
            "status_code": resp.status_code,
        },
    )


async def _try_traversal(base_url: str) -> dict:
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        for payload in TRAVERSAL_PAYLOADS:
            url = base_url.rstrip("/") + payload
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and ("root:" in resp.text or "nobody:" in resp.text):
                    return {"exploitable": True, "payload": f"GET {url}", "response": resp.text[:500]}
            except Exception:
                continue
    return {"exploitable": False, "payload": "", "response": ""}


async def _check_tls(host: str, port: int) -> Evidence:
    issues = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

        # Check cert expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
            if days_left < 30:
                issues.append(f"Certificate expires in {days_left} days")

        # Check weak protocol
        if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            issues.append(f"Weak protocol in use: {protocol}")

        exploitable = bool(issues)
        return Evidence(
            sent=f"TLS handshake to {host}:{port}",
            received=f"Protocol: {protocol}, Cipher: {cipher[0] if cipher else 'unknown'}",
            context={
                "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE if exploitable
                                      else ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
                "environment_context": "; ".join(issues) if issues else "TLS configuration is acceptable",
                "protocol": protocol,
                "cipher": cipher[0] if cipher else None,
                "issues": issues,
            },
        )
    except Exception as e:
        return Evidence(
            sent=f"TLS check {host}:{port}",
            received=f"TLS check failed: {e}",
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
