"""
Apache-specific validation plugin.

Checks performed (each is a single controlled HTTP request):

  1. Server-header version disclosure        — LOW
  2. Sensitive path exposure                  — HIGH if any returns 200
     (/server-status /server-info /.htaccess /wp-config.php.bak)
  3. HTTP methods                             — MEDIUM if TRACE/TRACK allowed
  4. Directory listing on /icons/             — MEDIUM if listing visible

Severity reported is the highest single severity observed. Severity flows
through `evidence.context["severity"]`, which the executor reads as an
override (Apache misconfig is not a CVE so cvss_score stays None).
"""

from __future__ import annotations

import re

import httpx

from apps.validation.models import CVE, Evidence, QueueItem, Service, ValidationStatus

_SENSITIVE_PATHS = (
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/wp-config.php.bak",
)
_DANGEROUS_METHODS = {"TRACE", "TRACK"}
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_VERSION_PATTERN = re.compile(r"Apache(?:/[\d.]+)?", re.IGNORECASE)
_DIR_LISTING_MARKERS = ("Index of", "<title>Index of")


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
        headers={"User-Agent": "ai-assist-tool/apache-plugin"},
    ) as client:
        # 1. Version disclosure
        try:
            r = await client.get(base_url + "/")
            sent.append(f"GET {base_url}/")
            server = r.headers.get("Server", "")
            if server and _VERSION_PATTERN.search(server):
                findings.append(f"Apache version disclosed: {server}")
                severities.append("low")
                received.append(f"Server: {server}")
        except httpx.HTTPError as e:
            received.append(f"GET / failed: {e}")

        # 2. Sensitive path exposure
        for path in _SENSITIVE_PATHS:
            url = base_url + path
            try:
                r = await client.get(url)
                sent.append(f"GET {url}")
                if r.status_code == 200:
                    body_preview = (r.text or "")[:100].replace("\n", " ")
                    findings.append(
                        f"Sensitive path {path} returned 200 (expected 403)"
                    )
                    severities.append("high")
                    received.append(f"{path} → 200: {body_preview}")
                else:
                    received.append(f"{path} → {r.status_code}")
            except httpx.HTTPError as e:
                received.append(f"{path} → error: {e}")

        # 3. HTTP methods (OPTIONS)
        try:
            r = await client.options(base_url + "/")
            sent.append(f"OPTIONS {base_url}/")
            allow = r.headers.get("Allow", "") or r.headers.get("allow", "")
            received.append(f"Allow: {allow or '(missing)'}")
            allowed_methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
            dangerous = allowed_methods & _DANGEROUS_METHODS
            if dangerous:
                findings.append(f"Dangerous HTTP methods allowed: {', '.join(sorted(dangerous))}")
                severities.append("medium")
        except httpx.HTTPError as e:
            received.append(f"OPTIONS / failed: {e}")

        # 4. Directory listing on /icons/
        try:
            r = await client.get(base_url + "/icons/")
            sent.append(f"GET {base_url}/icons/")
            body = (r.text or "")[:2000]
            if r.status_code == 200 and any(m in body for m in _DIR_LISTING_MARKERS):
                snippet = body[: body.find(">", body.find("Index of")) + 1] if "Index of" in body else body[:200]
                findings.append("Directory listing exposed on /icons/")
                severities.append("medium")
                received.append(f"/icons/ → 200 (listing visible): {snippet[:200]}")
            else:
                received.append(f"/icons/ → {r.status_code}")
        except httpx.HTTPError as e:
            received.append(f"GET /icons/ failed: {e}")

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
            "environment_context": "No Apache misconfigurations detected",
        },
    )


async def _get_host_ip(host_id: str) -> str:
    from apps.validation.database import get_db
    from apps.validation.repositories import HostRepository
    async with get_db() as db:
        repo = HostRepository(db)
        host = await repo.get_by_id(host_id)
    return host.ip if host else "unknown"
