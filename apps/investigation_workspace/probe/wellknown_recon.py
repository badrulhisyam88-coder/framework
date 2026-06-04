"""Well-known path and sensitive file disclosure probe — Recon phase.

Bootstrap-wired: runs concurrently with other Recon probes in
runtime._runner(). GET requests only; read-only.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx

from apps.investigation_workspace.probe.events import FindingEvent, StageEvent
from apps.investigation_workspace.probe.finding_id import generate_finding_id

WELLKNOWN_PATHS: tuple[str, ...] = (
    "/robots.txt",
    "/sitemap.xml",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/.well-known/openapi.json",
    "/.well-known/change-password",
)

SENSITIVE_FILE_PATHS: tuple[str, ...] = (
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.DS_Store",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
    "/config.bak",
    "/config.old",
    "/config.swp",
    "/web.config.bak",
)

_WELLKNOWN_SEVERITY: dict[str, str] = {
    "/robots.txt":                  "info",
    "/sitemap.xml":                 "info",
    "/humans.txt":                  "info",
    "/security.txt":                "info",
    "/.well-known/security.txt":    "info",
    "/.well-known/openapi.json":    "medium",
    "/.well-known/change-password": "info",
}

# Body signatures distinguishing real hits from custom error pages.
_BODY_SIGS: dict[str, re.Pattern[str]] = {
    "/.git/config": re.compile(r"\[core\]", re.IGNORECASE),
    "/.git/HEAD":   re.compile(r"^ref:", re.MULTILINE),
    "/.env":        re.compile(r"[A-Z_]+=", re.MULTILINE),
}

_ROBOTS_DISALLOW = re.compile(r"^Disallow:\s*(.+)$", re.MULTILINE)

_PROBE_ID = "wellknown_recon"


async def run_wellknown_probe(
    target: str,
    *,
    after_stage_index: int = 1,
) -> AsyncIterator[StageEvent | FindingEvent]:
    """Probe well-known and sensitive file paths. Emit on 2xx only."""
    parsed   = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    yield StageEvent(
        label   = "Probing well-known paths",
        actions = (
            f"Scanning {len(WELLKNOWN_PATHS)} well-known informational paths",
            f"Scanning {len(SENSITIVE_FILE_PATHS)} sensitive file paths",
            "GET only; 5 s timeout per path",
        ),
        tools      = ("httpx async client",),
        confidence = "—",
    )

    collected: list[FindingEvent] = []

    async with httpx.AsyncClient(
        timeout          = 5.0,
        follow_redirects = True,
        verify           = False,
    ) as client:
        # ── Well-known informational paths ────────────────────────────────
        for path in WELLKNOWN_PATHS:
            url = base_url + path
            try:
                resp = await client.get(url)
            except Exception:
                continue
            if resp.status_code not in (200, 201, 204):
                continue

            body_raw     = resp.text[:2000]
            body_sample  = body_raw[:200].replace("\x00", "")
            content_type = resp.headers.get("content-type", "") or ""
            severity     = _WELLKNOWN_SEVERITY.get(path, "info")

            next_actions: list[dict] = []
            if path == "/robots.txt":
                for m in _ROBOTS_DISALLOW.finditer(body_raw):
                    dp = m.group(1).strip()
                    if dp and dp != "/":
                        next_actions.append({
                            "probe_id":        "run_endpoint_enum",
                            "trigger":         "auto_fire",
                            "description":     f"Enumerate disallowed path from robots.txt: {dp}",
                            "required_inputs": [],
                            "produces":        "endpoint_inventory",
                        })

            finding_type = "wellknown_file_disclosed"
            collected.append(FindingEvent(
                after_stage_index = after_stage_index,
                finding_type      = finding_type,
                title             = f"Well-known file accessible: {path}",
                severity          = severity,
                description       = (
                    f"GET {path} returned HTTP {resp.status_code}. "
                    f"The file is publicly accessible."
                ),
                endpoint          = path,
                evidence          = {
                    "path":         path,
                    "status_code":  resp.status_code,
                    "content_type": content_type,
                    "body_bytes":   len(resp.content),
                    "body_sample":  body_sample,
                },
                phase             = "recon",
                id                = generate_finding_id(_PROBE_ID, target, path, finding_type),
                confidence        = "high",
                next_actions      = next_actions or None,
            ))

        # ── Sensitive file paths ──────────────────────────────────────────
        for path in SENSITIVE_FILE_PATHS:
            url = base_url + path
            try:
                resp = await client.get(url)
            except Exception:
                continue
            if resp.status_code not in (200, 201, 204):
                continue

            body_raw     = resp.text[:2000]
            body_sample  = body_raw[:200].replace("\x00", "")
            content_type = resp.headers.get("content-type", "") or ""

            sig        = _BODY_SIGS.get(path)
            confidence = "high" if (sig and sig.search(body_raw)) else "medium"

            finding_type = "sensitive_file_disclosed"
            collected.append(FindingEvent(
                after_stage_index = after_stage_index,
                finding_type      = finding_type,
                title             = f"Sensitive file accessible: {path}",
                severity          = "high",
                description       = (
                    f"GET {path} returned HTTP {resp.status_code}. "
                    f"Potentially sensitive file is publicly readable."
                ),
                endpoint          = path,
                evidence          = {
                    "path":         path,
                    "status_code":  resp.status_code,
                    "content_type": content_type,
                    "body_bytes":   len(resp.content),
                    "body_sample":  body_sample,
                },
                phase             = "recon",
                id                = generate_finding_id(_PROBE_ID, target, path, finding_type),
                confidence        = confidence,
                next_actions      = None,
            ))

    total = len(collected)
    yield StageEvent(
        label   = "Well-known path scan complete",
        actions = (
            f"Scanned {len(WELLKNOWN_PATHS)} informational paths",
            f"Scanned {len(SENSITIVE_FILE_PATHS)} sensitive file paths",
        ),
        tools      = ("httpx async client",),
        detected   = (
            (f"{total} accessible path(s) found",)
            if total else
            ("no well-known or sensitive files accessible",)
        ),
        confidence = "high",
    )
    for fe in collected:
        yield fe
