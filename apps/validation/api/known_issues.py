"""Known-issue (suppression rule) router.

Exposes CRUD for `KnownIssue` rules, plus a "test" preview that reports how
many existing open findings would be silenced by a rule right now. A separate
endpoint on the findings router (`/findings/{id}/mark-known-issue`) is the
primary way new rules are created from the UI.

Also hosts the CVE Watchlist endpoints, which share the same management page.
"""

from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from apps.validation.database import get_db
from apps.validation.engines.cve_matcher import CVEMatcher
from apps.validation.engines.fingerprint_normalizer import FingerprintNormalizer
from apps.validation.models import (
    KnownIssueMatchField,
    QueueItem,
    QueueStatus,
    ValidationType,
    WatchlistEntry,
    cvss_to_severity,
)
from apps.validation.repositories import (
    CVERepository,
    FindingRepository,
    HostRepository,
    KnownIssueRepository,
    QueueRepository,
    ServiceRepository,
    WatchlistRepository,
)
from apps.validation.services.suppression import match_rule
from sdk import Logger

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


def _label_for(field: KnownIssueMatchField, value: str) -> str:
    """Human-readable label for a rule's match criterion."""
    if field == KnownIssueMatchField.FINDING_TYPE:
        return "type only"
    if field == KnownIssueMatchField.FINDING_TYPE_PORT:
        return f"port {value}"
    if field == KnownIssueMatchField.FINDING_TYPE_EVIDENCE_CONTAINS:
        return f'evidence contains "{value}"'
    if field == KnownIssueMatchField.CVE_ID:
        return f"CVE {value}"
    if field == KnownIssueMatchField.FINDING_TYPE_VALIDATION_STATUS:
        return f"status={value}"
    return str(field)


@router.get("/known-issues-page", response_class=HTMLResponse)
async def known_issues_page(request: Request):
    """Render the Known Issues management page."""
    async with get_db() as db:
        repo = KnownIssueRepository(db)
        rules = await repo.list_all()

        watchlist_repo = WatchlistRepository(db)
        cve_repo = CVERepository(db)
        watchlist_entries = await watchlist_repo.list_all()
        watchlist_view = []
        for entry in watchlist_entries:
            cve = await cve_repo.get_by_id(entry.cve_id)
            watchlist_view.append({
                "entry": entry,
                "source_url": cve.source_url if cve else None,
            })

    rules_view = [
        {
            "rule": r,
            "label": _label_for(r.match_field, r.match_value),
        }
        for r in rules
    ]
    return templates.TemplateResponse(
        "known_issues.html",
        {
            "request": request,
            "rules": rules_view,
            "watchlist": watchlist_view,
            "watchlist_count": len(watchlist_view),
            "active": "known_issues",
        },
    )


@router.get("/known-issues")
async def list_known_issues():
    async with get_db() as db:
        repo = KnownIssueRepository(db)
        rules = await repo.list_all()
    return [r.model_dump(mode="json") for r in rules]


@router.delete("/known-issues/{rule_id}", response_class=HTMLResponse)
async def delete_known_issue(rule_id: str, request: Request):
    """Remove a rule and re-open any findings it was holding suppressed."""
    async with get_db() as db:
        repo = KnownIssueRepository(db)
        rule = await repo.get_by_id(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")

        finding_repo = FindingRepository(db)
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)

        # Reopen findings that were suppressed by this rule. We don't store
        # the rule_id on the finding; we re-evaluate against the remaining
        # rules and reopen those that match none of them.
        suppressed = [
            f for f in await finding_repo.list_all(limit=10_000)
            if f.status == "suppressed"
        ]
        await repo.delete(rule_id)
        remaining = await repo.list_all()

        reopened = 0
        for f in suppressed:
            service = (
                await service_repo.get_by_id(f.service_id) if f.service_id else None
            )
            still_matched = any(match_rule(f, r, service) for r in remaining)
            if not still_matched:
                await finding_repo.update_status(f.id, "open")
                reopened += 1

    Logger.info(
        "known_issue.deleted",
        extra={"rule_id": rule_id, "reopened": reopened},
    )
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="", status_code=200, headers={"HX-Refresh": "true"},
        )
    return HTMLResponse(content=f"deleted, reopened {reopened}", status_code=200)


@router.post("/known-issues/{rule_id}/test", response_class=HTMLResponse)
async def test_known_issue(rule_id: str, request: Request):
    """Preview: how many *currently open* findings would this rule suppress?"""
    async with get_db() as db:
        repo = KnownIssueRepository(db)
        rule = await repo.get_by_id(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        finding_repo = FindingRepository(db)
        service_repo = ServiceRepository(db)
        opens = await finding_repo.list_open()
        hits = 0
        for f in opens:
            service = (
                await service_repo.get_by_id(f.service_id) if f.service_id else None
            )
            if match_rule(f, rule, service):
                hits += 1
    return HTMLResponse(
        f'<span class="mono">{hits} open finding(s) would be suppressed</span>'
    )


# ---------------------------------------------------------------------------
# CVE Watchlist
# ---------------------------------------------------------------------------


def _select_watchlist_plugin(service_name: str | None, port: int) -> str:
    """Pick the validation plugin for an auto-approved watchlist hit."""
    name = (service_name or "").lower()
    if "ssh" in name or port == 22:
        return "ssh_plugin"
    if any(x in name for x in ("http", "www", "web")) or port in (80, 443, 8080, 8443):
        return "web_plugin"
    if "smb" in name or port in (445, 139):
        return "smb_plugin"
    if any(x in name for x in ("mysql", "mssql", "postgresql")) or port in (3306, 1433, 5432):
        return "sqli_plugin"
    return "generic_plugin"


async def _sweep_watchlist(cve_ids: set[str]) -> int:
    """
    Run CVE matching against every known service and auto-execute matches
    whose cve_id is in `cve_ids`. Returns the count of executions launched.

    Used both by the inline POST /watchlist add path (limited to the new
    cve_id) and by POST /watchlist/check-assets (full sweep).
    """
    if not cve_ids:
        return 0

    from apps.validation.services.executor import ExecutorService

    normalizer = FingerprintNormalizer()
    matcher = CVEMatcher()
    executor = ExecutorService()

    async with get_db() as db:
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        hosts = await host_repo.list_all()
        services: list = []
        for host in hosts:
            services.extend(await service_repo.list_by_host(host.id))

    hits = 0
    for service in services:
        normalized = normalizer.normalize(service)
        if not normalized:
            continue
        try:
            matches = await matcher.match(service, normalized)
        except Exception as e:
            Logger.error(
                "watchlist.match.error",
                extra={"service_id": service.id, "error": str(e)},
            )
            continue

        for match in matches:
            if match.cve.cve_id not in cve_ids:
                continue
            try:
                async with get_db() as db:
                    queue_repo = QueueRepository(db)
                    if await queue_repo.exists_pending(
                        service.host_id, service.id, ValidationType.CVE_POC
                    ):
                        continue
                    plugin = _select_watchlist_plugin(service.service_name, service.port)
                    item = QueueItem(
                        host_id=service.host_id,
                        service_id=service.id,
                        cve_id=match.cve.cve_id,
                        validation_type=ValidationType.CVE_POC,
                        plugin_name=plugin,
                        profile_name="cve_poc",
                        status=QueueStatus.APPROVED,
                        notes="Auto-approved: CVE Watchlist",
                    )
                    await queue_repo.insert(item)
                    await queue_repo.approve(item.id, "Auto-approved: CVE Watchlist")

                Logger.info(
                    "watchlist.hit",
                    extra={
                        "cve_id": match.cve.cve_id,
                        "service_id": service.id,
                        "host_id": service.host_id,
                    },
                )

                async with get_db() as db:
                    watchlist_repo = WatchlistRepository(db)
                    await watchlist_repo.increment_hit(match.cve.cve_id)

                await executor.execute(item.id)
                hits += 1
            except Exception as e:
                Logger.error(
                    "watchlist.execute.error",
                    extra={
                        "cve_id": match.cve.cve_id,
                        "service_id": service.id,
                        "error": str(e),
                    },
                )
                continue

    return hits


def _watchlist_row_html(entry: WatchlistEntry, source_url: str | None) -> str:
    """Render a single watchlist table row for HTMX append swaps."""
    cve_cell = (
        f'<a href="{source_url}" target="_blank" class="mono" '
        f'style="color:var(--accent);font-size:12px;">{entry.cve_id}</a>'
        if source_url else
        f'<span class="mono" style="font-size:12px;">{entry.cve_id}</span>'
    )
    sev = (entry.severity or "info").lower()
    description = (entry.description or "")
    if len(description) > 160:
        description = description[:160] + "…"
    last_hit = entry.last_hit.strftime("%m-%d %H:%M") if entry.last_hit else "—"
    desc_style = "font-size:13px;color:var(--text-secondary);max-width:380px;"
    return (
        f'<tr id="wl-row-{entry.id}">'
        f'<td>{cve_cell}</td>'
        f'<td style="{desc_style}">{description}</td>'
        f'<td><span class="severity severity-{sev}">{sev}</span></td>'
        f'<td class="mono">{entry.hit_count}</td>'
        f'<td class="text-muted mono" style="font-size:11px;">{last_hit}</td>'
        f'<td>'
        f'<button class="btn btn-reject btn-sm" '
        f'hx-delete="/api/v1/validation/watchlist/{entry.id}" '
        f'hx-confirm="Remove this CVE from the watchlist?" '
        f'hx-target="#wl-row-{entry.id}" hx-swap="outerHTML">✕ Remove</button>'
        f'</td>'
        f'</tr>'
    )


@router.get("/watchlist")
async def list_watchlist():
    """JSON list of every watchlist entry, newest first."""
    async with get_db() as db:
        repo = WatchlistRepository(db)
        entries = await repo.list_all()
    return [e.model_dump(mode="json") for e in entries]


@router.post("/watchlist")
async def add_to_watchlist(request: Request, cve_id: str = Form(...)):
    """Add a CVE to the watchlist and immediately sweep existing assets."""
    cve_id = (cve_id or "").strip().upper()
    if not cve_id or not cve_id.startswith("CVE-"):
        if request.headers.get("HX-Request"):
            return HTMLResponse(
                '<span class="text-muted">Invalid CVE id — must start with CVE-.</span>',
                status_code=400,
            )
        return JSONResponse(
            {"detail": "Invalid CVE id — must start with CVE-."}, status_code=400
        )

    async with get_db() as db:
        cve_repo = CVERepository(db)
        cve = await cve_repo.get_by_id(cve_id)
        if not cve:
            return JSONResponse(
                {"detail": "CVE not in local database — run NVD sync first."},
                status_code=404,
            )

        watchlist_repo = WatchlistRepository(db)
        existing = await watchlist_repo.get_by_cve_id(cve_id)
        if existing:
            return JSONResponse(
                {"detail": "CVE already on the watchlist."}, status_code=409
            )

        severity = cvss_to_severity(cve.cvss_score)
        entry = WatchlistEntry(
            cve_id=cve.cve_id,
            description=cve.description,
            cvss_score=cve.cvss_score,
            severity=str(severity),
        )
        await watchlist_repo.insert(entry)

    Logger.info(
        "watchlist.added",
        extra={"cve_id": cve.cve_id, "cvss": cve.cvss_score},
    )

    # Immediate sweep — count hits so the UI can report.
    try:
        hits = await _sweep_watchlist({cve.cve_id})
    except Exception as e:
        Logger.error("watchlist.sweep.error", extra={"error": str(e), "cve_id": cve.cve_id})
        hits = 0

    async with get_db() as db:
        watchlist_repo = WatchlistRepository(db)
        refreshed = await watchlist_repo.get_by_id(entry.id) or entry
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        hosts = await host_repo.list_all()
        service_count = 0
        for host in hosts:
            service_count += len(await service_repo.list_by_host(host.id))

    if request.headers.get("HX-Request"):
        summary = (
            f'<div id="watchlist-summary" class="text-muted" '
            f'style="font-size:12px;margin-top:8px;" hx-swap-oob="true">'
            f'{cve.cve_id} added. Checking {service_count} service(s)… '
            f'{hits} hit(s) found.'
            f'</div>'
        )
        body = _watchlist_row_html(refreshed, cve.source_url) + summary
        return HTMLResponse(body)

    return {
        "entry": refreshed.model_dump(mode="json"),
        "services_checked": service_count,
        "hits": hits,
    }


@router.delete("/watchlist/{entry_id}", response_class=HTMLResponse)
async def remove_from_watchlist(entry_id: str, request: Request):
    """Delete a watchlist entry. HTMX swap removes the row in place."""
    async with get_db() as db:
        repo = WatchlistRepository(db)
        entry = await repo.get_by_id(entry_id)
        if not entry:
            raise HTTPException(status_code=404, detail="Watchlist entry not found")
        await repo.delete(entry_id)

    Logger.info("watchlist.removed", extra={"entry_id": entry_id, "cve_id": entry.cve_id})

    if request.headers.get("HX-Request"):
        return HTMLResponse(content="", status_code=200)
    return HTMLResponse(content="deleted", status_code=200)


@router.post("/watchlist/check-assets")
async def recheck_watchlist(request: Request):
    """Re-run the entire watchlist against every known service."""
    async with get_db() as db:
        repo = WatchlistRepository(db)
        entries = await repo.list_all()

    cve_ids = {e.cve_id for e in entries}
    try:
        hits = await _sweep_watchlist(cve_ids)
    except Exception as e:
        Logger.error("watchlist.recheck.error", extra={"error": str(e)})
        hits = 0

    payload = {"entries": len(entries), "hits": hits}
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="", status_code=200, headers={"HX-Refresh": "true"},
        )
    return payload
