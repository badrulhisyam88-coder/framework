"""History + Dashboard router."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apps.validation.database import get_db
from apps.validation.repositories import (
    AssetRepository,
    CVERepository,
    FindingRepository,
    HistoryRepository,
    HostRepository,
    QueueRepository,
    ServiceRepository,
)

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


# Severity priority for sorting open findings (critical first).
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Hosts/targets considered "test" entries — never surface in Recent Activity.
_TEST_TARGETS = {"127.0.0.1", "localhost"}


def _ago(dt: datetime) -> str:
    """Human-friendly relative time string."""
    if dt is None:
        return "—"
    delta = datetime.utcnow() - dt
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    async with get_db() as db:
        repo = HistoryRepository(db)
        entries = await repo.list_all()
    return templates.TemplateResponse(
        "history.html", {"request": request, "entries": entries}
    )


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    now = datetime.utcnow()
    seven_days_ago = now - timedelta(days=7)
    thirty_days_ago = now - timedelta(days=30)

    async with get_db() as db:
        host_repo = HostRepository(db)
        service_repo = ServiceRepository(db)
        finding_repo = FindingRepository(db)
        queue_repo = QueueRepository(db)
        cve_repo = CVERepository(db)
        history_repo = HistoryRepository(db)
        asset_repo = AssetRepository(db)

        total_hosts = await host_repo.count()
        total_services = await service_repo.count()
        hosts = await host_repo.list_all()
        asset_name_by_target = await asset_repo.map_target_to_name()

        open_findings_all = await finding_repo.list_open()
        # Enrich findings with host/service/cve in one pass (avoid N+1 fan-out).
        host_cache: dict[str, object] = {}
        service_cache: dict[str, object] = {}
        cve_cache: dict[str, object] = {}
        for f in open_findings_all:
            if f.host_id not in host_cache:
                host_cache[f.host_id] = await host_repo.get_by_id(f.host_id)
            f.host = host_cache[f.host_id]
            if f.host:
                f.asset_name = asset_name_by_target.get(f.host.ip)
            if f.service_id:
                if f.service_id not in service_cache:
                    service_cache[f.service_id] = await service_repo.get_by_id(f.service_id)
                f.service = service_cache[f.service_id]
            if f.cve_id:
                if f.cve_id not in cve_cache:
                    cve_cache[f.cve_id] = await cve_repo.get_by_id(f.cve_id)
                f.cve = cve_cache[f.cve_id]

        queue_counts = await queue_repo.count_by_status()
        all_queue_items = await queue_repo.list_all(limit=10000)
        history_entries = await history_repo.list_all(limit=200)

    # --- Section 1: Overview ---
    open_findings_count = len(open_findings_all)
    critical_high_count = sum(
        1 for f in open_findings_all if f.severity in ("critical", "high")
    )
    pending_queue_count = queue_counts.get("pending", 0)

    # Last scan from history entries
    last_scan_target: str | None = None
    last_scan_ago: str | None = None
    for entry in history_entries:
        if entry.action == "scan" and entry.detail:
            target = entry.detail.get("target")
            if target:
                last_scan_target = target
                last_scan_ago = _ago(entry.timestamp)
                break

    # --- Section 2: Open Findings Summary (cap 50, severity then recency) ---
    open_findings_sorted = sorted(
        open_findings_all,
        key=lambda f: (
            _SEVERITY_RANK.get(str(f.severity), 99),
            -f.timestamp.timestamp(),
        ),
    )[:50]

    # --- Section 3: Recent Activity (last 7 days, max 10) ---
    recent_activity: list = []
    seen_scan_keys: set[str] = set()
    for entry in history_entries:
        if entry.timestamp < seven_days_ago:
            continue
        if entry.action == "scan":
            detail = entry.detail or {}
            target = (detail.get("target") or "").strip()
            if not target or target in _TEST_TARGETS:
                continue
            new_hosts = detail.get("new_hosts", 0)
            if not new_hosts or new_hosts <= 0:
                continue
            # Dedupe consecutive scans for same target on same date.
            date_key = entry.timestamp.strftime("%Y-%m-%d")
            dedupe_key = f"{target}|{date_key}"
            if dedupe_key in seen_scan_keys:
                continue
            seen_scan_keys.add(dedupe_key)
            recent_activity.append(
                type("Activity", (), {
                    "timestamp": entry.timestamp,
                    "summary": f"Discovered {new_hosts} new host(s) scanning {target}",
                })()
            )
        elif entry.action == "finding":
            summary = entry.summary or ""
            if summary.startswith("CONFIRMED EXPLOITABLE") or summary.startswith("NOT EXPLOITABLE"):
                recent_activity.append(
                    type("Activity", (), {
                        "timestamp": entry.timestamp,
                        "summary": summary,
                    })()
                )
        if len(recent_activity) >= 10:
            break

    # --- Section 4: Infrastructure Health ---
    def _label(ip: str) -> str:
        name = asset_name_by_target.get(ip)
        return f"{name} ({ip})" if name else ip

    # 4a. Hosts with critical open findings (max 5)
    critical_host_ids: list[str] = []
    seen_host_ids: set[str] = set()
    for f in open_findings_all:
        if str(f.severity) == "critical" and f.host_id not in seen_host_ids:
            seen_host_ids.add(f.host_id)
            critical_host_ids.append(f.host_id)
            if len(critical_host_ids) >= 5:
                break
    critical_hosts: list[str] = []
    for hid in critical_host_ids:
        h = host_cache.get(hid)
        if h is not None:
            critical_hosts.append(_label(h.ip))
        else:
            critical_hosts.append(hid[:8])

    # 4b. Hosts never validated — hosts that have at least one queue item
    #     but no queue item has ever reached 'approved' or 'completed'.
    queue_items_by_host: dict[str, list] = {}
    for qi in all_queue_items:
        queue_items_by_host.setdefault(qi.host_id, []).append(qi)

    never_validated_hosts: list[str] = []
    for h in hosts:
        items = queue_items_by_host.get(h.id)
        if not items:
            continue
        has_validated = any(
            str(qi.status) in ("approved", "completed") for qi in items
        )
        if not has_validated:
            never_validated_hosts.append(_label(h.ip))
            if len(never_validated_hosts) >= 5:
                break

    # 4c. Hosts not scanned in 30+ days (max 5)
    stale_hosts: list[str] = []
    for h in hosts:
        if h.last_seen < thirty_days_ago:
            stale_hosts.append(_label(h.ip))
            if len(stale_hosts) >= 5:
                break

    context = {
        "request": request,
        "active": "dashboard",
        # Section 1
        "total_hosts": total_hosts,
        "total_services": total_services,
        "open_findings_count": open_findings_count,
        "critical_high_count": critical_high_count,
        "pending_queue_count": pending_queue_count,
        "last_scan_target": last_scan_target,
        "last_scan_ago": last_scan_ago,
        # Section 2
        "open_findings": open_findings_sorted,
        # Section 3
        "recent_activity": recent_activity,
        # Section 4
        "critical_hosts": critical_hosts,
        "never_validated_hosts": never_validated_hosts,
        "stale_hosts": stale_hosts,
        # Sidebar badge
        "queue_count": pending_queue_count,
    }

    return templates.TemplateResponse("dashboard.html", context)
