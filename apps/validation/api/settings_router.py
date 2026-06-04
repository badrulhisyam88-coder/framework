"""Settings router — NVD sync, configuration display."""
import os
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from apps.validation.config import (
    AUTO_ARCHIVE_DEFAULT,
    RETAIN_EXPLOITABLE_DEFAULT,
    RETAIN_NOT_EXPLOITABLE_DEFAULT,
    RETAIN_REJECTED_DEFAULT,
    WORKERS_MAX,
    WORKERS_MIN,
    get_auto_archive,
    get_default_workers,
    get_retention_days,
    set_auto_archive,
    set_default_workers,
    set_retention_days,
)
from apps.validation.database import get_db
from apps.validation.engines.nvd_sync import InvalidNVDApiKey, NVDSyncEngine
from apps.validation.repositories import (
    CVERepository,
    FindingRepository,
    KnownIssueRepository,
    QueueRepository,
    ServiceRepository,
)
from apps.validation.services.suppression import first_matching_rule
from sdk import Logger

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    async with get_db() as db:
        cve_repo = CVERepository(db)
        queue_repo = QueueRepository(db)
        known_repo = KnownIssueRepository(db)
        finding_repo = FindingRepository(db)
        total_cves = await cve_repo.count()
        last_sync = await cve_repo.get_sync_meta("last_sync")
        stats = await queue_repo.stats()
        suppression_stats = await _suppression_stats(known_repo, finding_repo)

    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "total_cves": total_cves,
            "last_sync": last_sync or "Never",
            "has_api_key": bool(os.getenv("TOOL_NVD_API_KEY")),
            "default_workers": get_default_workers(),
            "workers_min": WORKERS_MIN,
            "workers_max": WORKERS_MAX,
            "retain_exploitable": get_retention_days(
                "TOOL_RETAIN_EXPLOITABLE", RETAIN_EXPLOITABLE_DEFAULT
            ),
            "retain_not_exploitable": get_retention_days(
                "TOOL_RETAIN_NOT_EXPLOITABLE", RETAIN_NOT_EXPLOITABLE_DEFAULT
            ),
            "retain_rejected": get_retention_days(
                "TOOL_RETAIN_REJECTED", RETAIN_REJECTED_DEFAULT
            ),
            "auto_archive": get_auto_archive(),
            "auto_archive_default": AUTO_ARCHIVE_DEFAULT,
            "queue_stats": stats,
            "suppression_stats": suppression_stats,
        },
    )


@router.post("/settings/nvd-sync")
async def trigger_nvd_sync(full: bool = False):
    api_key = os.getenv("TOOL_NVD_API_KEY")
    engine = NVDSyncEngine(api_key=api_key or None)
    try:
        if full:
            return await engine.sync_full()
        return await engine.sync_recent(days=7)
    except InvalidNVDApiKey as e:
        # 400 + readable detail beats a generic 500 — the user can fix .env.
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/settings/workers", response_class=HTMLResponse)
async def save_default_workers(workers: int = Form(...)):
    saved = set_default_workers(workers)
    return HTMLResponse(
        f'<span class="text-muted">Default workers saved: '
        f'<span class="mono">{saved}</span></span>'
    )


@router.get("/settings/queue-stats")
async def queue_stats():
    """Return queue lifecycle stats for the settings health card."""
    async with get_db() as db:
        repo = QueueRepository(db)
        return await repo.stats()


async def _suppression_stats(
    known_repo: KnownIssueRepository,
    finding_repo: FindingRepository,
) -> dict[str, int]:
    """Counts for the Settings → Suppression Statistics card."""
    from datetime import datetime, timezone
    rules = await known_repo.list_all()
    total_rules = len(rules)
    all_time_hits = sum(r.hit_count for r in rules)
    today = datetime.now(timezone.utc).date()
    hits_today = 0
    for r in rules:
        if r.last_hit and r.last_hit.date() == today:
            # last_hit only records the most recent fire; today's count is
            # an approximation — count the rule once if its last hit was today.
            hits_today += 1
    return {
        "total_rules": total_rules,
        "all_time_hits": all_time_hits,
        "today_hits": hits_today,
    }


@router.post("/settings/rescan-suppressions", response_class=HTMLResponse)
async def rescan_suppressions(request: Request):
    """Re-evaluate all open findings against current known_issue rules.

    Findings that match any rule become `suppressed`; the matching rule's
    hit counter is bumped. Returns an HTMX fragment (or JSON) with the count.
    """
    async with get_db() as db:
        known_repo = KnownIssueRepository(db)
        finding_repo = FindingRepository(db)
        service_repo = ServiceRepository(db)

        rules = await known_repo.list_all()
        opens = await finding_repo.list_open()
        suppressed = 0
        for f in opens:
            service = (
                await service_repo.get_by_id(f.service_id) if f.service_id else None
            )
            matched = first_matching_rule(f, rules, service)
            if matched:
                await finding_repo.set_suppressed(f.id, matched.reason)
                await known_repo.record_hit(matched.id)
                suppressed += 1
    Logger.info("known_issue.rescan", extra={"suppressed": suppressed})
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            f'<span class="mono">Rescan complete — suppressed '
            f'{suppressed} open finding(s)</span>'
        )
    return {"suppressed": suppressed}


@router.post("/settings/retention", response_class=HTMLResponse)
async def save_retention(
    retain_exploitable: int = Form(...),
    retain_not_exploitable: int = Form(...),
    retain_rejected: int = Form(...),
    auto_archive: str | None = Form(default=None),
):
    """Persist queue retention settings to the override file."""
    ex = set_retention_days("TOOL_RETAIN_EXPLOITABLE", retain_exploitable)
    nx = set_retention_days("TOOL_RETAIN_NOT_EXPLOITABLE", retain_not_exploitable)
    rj = set_retention_days("TOOL_RETAIN_REJECTED", retain_rejected)
    auto = set_auto_archive(auto_archive in ("on", "true", "1", "yes"))
    return HTMLResponse(
        '<span class="text-muted">Retention saved: '
        f'<span class="mono">exploitable={ex}d, not-exploitable={nx}d, '
        f'rejected={rj}d, auto-archive={"on" if auto else "off"}</span></span>'
    )
