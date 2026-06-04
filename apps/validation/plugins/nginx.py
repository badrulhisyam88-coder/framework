"""
Nginx-specific validation plugin.

Checks performed (single controlled HTTP request each):

  1. Server-header version disclosure          — LOW  (nginx/X.X.X)
  2. Default nginx welcome page                — LOW  ("Welcome to nginx")
  3. Common misconfig paths                    — HIGH if any returns 200
     (/nginx_status /.git/HEAD /.env)
  4. Security headers                          — LOW if multiple missing
     (reuses the SECURITY_HEADERS list from web_plugin)

Severity reported is the highest single severity observed and is passed
to the executor through `evidence.context["severity"]`.
"""

from __future__ import annotations

import re

import httpx

from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus
from apps.validation.plugins.web import SECURITY_HEADERS

_MISCONFIG_PATHS = (
    "/nginx_status",
    "/.git/HEAD",
    "/.env",
)
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_NGINX_VERSION_PATTERN = re.compile(r"nginx/[\d.]+", re.IGNORECASE)
_DEFAULT_PAGE_MARKER = "Welcome to nginx"


async def run(item: QueueItem, service: Service | None, cve: CVE | None) -> Evidence:
    if not service:
        return Evidence(
            context={
                "validation_status": ValidationStatus.CVE_MATCHED,
                "environment_context": "Service not found",
            }
        )

    host_ip = await _get_host_ip(item.host_id)
    scheme = _scheme(service)
    base_url = f"{scheme}://{host_ip}:{service.port}"

    sent: list[str] = []
    received: list[str] = []
    findings: list[str] = []
    severities: list[str] = []

    timeout = httpx.Timeout(8.0, connect=4.0)
    async with httpx.AsyncClient(
        verify=False, timeout=timeout, follow_redirects=False,
        headers={"User-Agent": "ai-assist-tool/nginx-plugin"},
    ) as client:
        # 1 & 2 & 4: single GET / covers version, default page, security headers
        try:
            r = await client.get(base_url + "/")
            sent.append(f"GET {base_url}/")
            server = r.headers.get("Server", "")
            received.append(f"Server: {server or '(none)'}")
            if server and _NGINX_VERSION_PATTERN.search(server):
                findings.append(f"Nginx version disclosed: {server}")
                severities.append("low")

            body = (r.text or "")[:4000]
            if _DEFAULT_PAGE_MARKER in body:
                findings.append('Default nginx welcome page exposed ("Welcome to nginx")')
                severities.append("low")

            missing = [h for h in SECURITY_HEADERS if h not in r.headers]
            received.append(
                f"Security headers: "
                f"{len(SECURITY_HEADERS) - len(missing)}/{len(SECURITY_HEADERS)} present"
            )
            if len(missing) >= 3:
                findings.append(f"Missing security headers: {', '.join(missing)}")
                severities.append("low")
        except httpx.HTTPError as e:
            received.append(f"GET / failed: {e}")

        # 3: misconfig paths
        for path in _MISCONFIG_PATHS:
            url = base_url + path
            try:
                r = await client.get(url)
                sent.append(f"GET {url}")
                if r.status_code == 200:
                    body_preview = (r.text or "")[:100].replace("\n", " ")
                    findings.append(
                        f"Misconfig path {path} returned 200 (expected 403)"
                    )
                    severities.append("high")
                    received.append(f"{path} → 200: {body_preview}")
                else:
                    received.append(f"{path} → {r.status_code}")
            except httpx.HTTPError as e:
                received.append(f"{path} → error: {e}")

    return _build_evidence(sent, received, findings, severities)


def _scheme(service: Service) -> str:
    name = (service.service_name or "").lower()
    if service.port in (443, 8443) or "ssl" in name or "https" in name:
        return "https"
    return "http"


def _build_evidence(
    sent: list[str], received: list[str], findings: list[str], severities: list[str]
) -> Evidence:
    if findings:
        highest = max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0))
        return Evidence(
            sent="\n".join(sent),
            received="\n".join(received),
            context={
                "validation_status": ValidationStatus.VALIDATED_EXPLOITABLE,
                "environment_context": "; ".join(findings),
                "severity": highest,
                "issues": findings,
            },
        )
    return Evidence(
        sent="\n".join(sent),
        received="\n".join(received),
        context={
            "validation_status": ValidationStatus.VALIDATED_NOT_EXPLOITABLE,
            "environment_context": "No nginx misconfigurations detected",
        },
    )


async def _get_host_ip(host_id: str) -> str:
    from apps.validation.database import get_db
    from apps.validation.repositories import HostRepository
    async with get_db() as db:
        repo = HostRepository(db)
        host = await repo.get_by_id(host_id)
    return host.ip if host else "unknown"
