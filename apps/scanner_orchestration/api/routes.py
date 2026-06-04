"""Scanner Orchestration API routes.

Mounted under /api/v1/validation/scanner by apps/validation/api/__init__.py.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from apps.scanner_orchestration.adapters import (
    NmapAdapter,
    NucleiAdapter,
    ZAPAdapter,
)
from apps.scanner_orchestration.services.orchestration_service import OrchestrationService
from apps.scanner_orchestration.target_resolution.ssrf_guard import validate_target

# Modules removed in PR VESTIGE-1 — stubs keep routes registered and app bootable.
ALL_PROFILES: list = []
SCANNER_STAGE_LABELS: dict = {}
profile_registry: dict = {}
from apps.validation.database import get_db

router = APIRouter(prefix="/scanner", tags=["scanner-orchestration"])
templates = Jinja2Templates(directory="frontend/templates")


def _scan_confidence(scan: Any) -> tuple[str, str]:
    """Return (state, message) for a scan.

    state ∈ ok | warn | error | pending
    message is investigation-centric — no adapter/queue language.
    """
    status_str = str(scan.status)
    if status_str == "queued":
        return "pending", "Preparing to launch"
    if status_str == "running":
        return "pending", "Investigation running…"
    if status_str == "failed":
        return "error", "Investigation could not complete"
    if status_str == "completed":
        if scan.error_message:
            if scan.findings_count > 0:
                return "warn", f"Partial — {scan.findings_count} finding(s) · scanner unavailable"
            return "warn", "Degraded — scanner unavailable, no findings"
        if scan.findings_count > 0:
            return "ok", f"{scan.findings_count} finding(s) identified"
        return "ok", "No findings — target appears clear"
    return "pending", status_str

_ADAPTERS = {
    "nmap": NmapAdapter,
    "zap": ZAPAdapter,
    "nuclei": NucleiAdapter,
}


class StartScanRequest(BaseModel):
    scanner_type: str
    profile_id: str = "quick_web_scan"
    target: str | None = None   # overrides investigation target if provided


class StartRunRequest(BaseModel):
    profile_id: str = "quick_web_scan"
    target: str | None = None   # overrides investigation target if provided


# ── Scanner catalogue ──────────────────────────────────────────────────────


@router.get("/scanners")
async def list_scanners():
    """List available scanners with availability status and version info where applicable."""
    results = []
    for scanner_type, cls in _ADAPTERS.items():
        adapter = cls()
        available = await adapter.check_available()
        entry: dict = {"scanner_type": scanner_type, "available": available}
        # Include ZAP version and API URL for diagnostics
        if scanner_type == "zap":
            import os
            entry["api_url"] = os.environ.get("ZAP_API_URL", "http://localhost:8080")
            if available:
                version = await adapter.get_version()
                entry["version"] = version
            else:
                entry["unavailable_reason"] = (
                    "ZAP daemon not reachable. "
                    "Run: docker compose up zap  (ZAP takes ~60s to start)"
                )
        results.append(entry)
    return results


@router.get("/profiles")
async def list_profiles():
    return [
        {
            "profile_id": p.profile_id,
            "title": p.title,
            "description": p.description,
            "scanners": p.scanners,
            "estimated_duration": p.estimated_duration,
            "investigation_stage": p.investigation_stage,
        }
        for p in ALL_PROFILES
    ]


# ── Scan lifecycle ─────────────────────────────────────────────────────────


@router.post("/investigations/{investigation_id}/scans")
async def start_scan(investigation_id: str, body: StartScanRequest):
    if body.scanner_type not in _ADAPTERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scanner: {body.scanner_type}. "
                   f"Available: {list(_ADAPTERS)}",
        )
    async with get_db() as db:
        from apps.investigation_core.services.investigation_service import (
            InvestigationService,
        )
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        target = body.target or (inv.targets[0] if inv.targets else None)
        if not target:
            raise HTTPException(
                status_code=400,
                detail="No target specified and investigation has no targets.",
            )

        allowed, reason = validate_target(target)
        if not allowed:
            raise HTTPException(status_code=422, detail=reason)

        svc = OrchestrationService(db)
        scan = await svc.start_scan(
            investigation_id,
            body.scanner_type,
            target,
            profile_id=body.profile_id,
        )
    return scan.model_dump(mode="json")


@router.post("/investigations/{investigation_id}/runs")
async def start_investigation_run(investigation_id: str, body: StartRunRequest):
    """Launch a full investigation run — one execution per scanner in the profile,
    run sequentially under a shared group_id.  The canonical launch endpoint."""
    async with get_db() as db:
        from apps.investigation_core.services.investigation_service import (
            InvestigationService,
        )
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        target = body.target or (inv.targets[0] if inv.targets else None)
        if not target:
            raise HTTPException(
                status_code=400,
                detail="No target specified and investigation has no targets.",
            )

        # SSRF guard — validate target against platform policy
        allowed, reason = validate_target(target)
        if not allowed:
            raise HTTPException(status_code=422, detail=reason)

        svc = OrchestrationService(db)

        # Rate limit — block if an active run is already in progress
        runs = await svc.list_runs(investigation_id, limit=5)
        active = [r for r in runs if not r.is_terminal]
        if active:
            raise HTTPException(
                status_code=429,
                detail=(
                    "An investigation run is already in progress. "
                    "Wait for it to complete before launching another."
                ),
            )

        group_id, scans = await svc.start_investigation_run(
            investigation_id, body.profile_id, target
        )
    return {
        "group_id": group_id,
        "scans": [s.model_dump(mode="json") for s in scans],
    }


@router.get("/investigations/{investigation_id}/scans")
async def list_scans(investigation_id: str):
    async with get_db() as db:
        svc = OrchestrationService(db)
        scans = await svc.list_scans(investigation_id)
    return [s.model_dump(mode="json") for s in scans]


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    async with get_db() as db:
        svc = OrchestrationService(db)
        scan = await svc.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.model_dump(mode="json")


@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    async with get_db() as db:
        svc = OrchestrationService(db)
        scan = await svc.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = await svc.list_findings(scan_id)
    return [f.model_dump(mode="json") for f in findings]


@router.get("/investigations/{investigation_id}/findings")
async def get_investigation_findings(investigation_id: str):
    async with get_db() as db:
        svc = OrchestrationService(db)
        findings = await svc.list_all_findings(investigation_id)
    return [f.model_dump(mode="json") for f in findings]


# ── Investigation export ───────────────────────────────────────────────────
# Routes moved to apps/investigation_workspace/api/routes.py (Phase 9).
# Kept here as stubs to avoid breaking any existing client references.


@router.get(
    "/investigations/{investigation_id}/export/partial",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def export_partial_legacy(investigation_id: str, request: Request):
    """Deprecated — use /workspace/investigations/{id}/export/partial."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(
        url=f"/api/v1/validation/workspace/investigations/{investigation_id}/export/partial",
        status_code=308,
    )


# ── Target resolution & diagnostics ───────────────────────────────────────


@router.get("/resolve")
async def resolve_target(url: str):
    raise HTTPException(status_code=503, detail="Target resolver unavailable")


@router.get("/diagnose")
async def diagnose_target(url: str):
    raise HTTPException(status_code=503, detail="Diagnostics service unavailable")


@router.get("/target-diagnostics/partial", response_class=HTMLResponse)
async def target_diagnostics_partial(url: str, request: Request):
    return HTMLResponse("<p style='padding:1rem'>Target diagnostics unavailable.</p>", status_code=503)


# ── HTMX partials ──────────────────────────────────────────────────────────


@router.get(
    "/investigations/{investigation_id}/scans/partial",
    response_class=HTMLResponse,
)
async def scans_partial(investigation_id: str, request: Request):
    async with get_db() as db:
        from apps.investigation_core.services.investigation_service import (
            InvestigationService,
        )
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        svc = OrchestrationService(db)
        runs = await svc.list_runs(investigation_id, limit=10)
        summary = {}

        # Aggregate findings from the most recent run (across all its stages)
        latest_run = runs[0] if runs else None
        latest_findings = []
        latest_scan = None
        if latest_run:
            completed = [s for s in latest_run.scans if str(s.status) == "completed"]
            if completed:
                latest_scan = completed[0]
                if latest_run.group_id:
                    # Multi-stage run — aggregate + deduplicate across all stages
                    latest_findings = await svc.list_run_findings(latest_run.group_id)
                else:
                    # Legacy ungrouped single scan
                    latest_findings = await svc.list_findings(latest_scan.scan_id)

        # Skills count for the completion bar — must be inside the DB block
        from apps.investigation_core.progression.storage.mastery_repo import MasteryRepository
        mastery_repo = MasteryRepository(db)
        mastery_records = await mastery_repo.list_for_investigation(investigation_id)
        skills_count = sum(
            1 for m in mastery_records
            if str(m.status) in ("in_progress", "completed", "mastered")
        )

    # Scanner availability — richer than bool: reachable | starting | degraded | unavailable
    scanner_availability: dict[str, str] = {}
    scanner_status_detail: dict[str, str] = {}
    for name, cls in _ADAPTERS.items():
        try:
            adapter = cls()
            if hasattr(adapter, "get_availability_status"):
                result = await adapter.get_availability_status()
                scanner_availability[name] = result["status"]
                scanner_status_detail[name] = result.get("detail", "")
            else:
                ok = await adapter.check_available()
                scanner_availability[name] = "reachable" if ok else "unavailable"
                scanner_status_detail[name] = ""
        except Exception:
            scanner_availability[name] = "unavailable"
            scanner_status_detail[name] = ""

    # Profile capability — derived from scanner_availability per profile's scanner list.
    # state: available | degraded | starting | unavailable
    # first_available_scanner: best scanner to use for this profile right now.
    profile_capability: dict[str, dict] = {}
    for profile in ALL_PROFILES:
        avail = [s for s in profile.scanners if scanner_availability.get(s) == "reachable"]
        starting_s = [s for s in profile.scanners if scanner_availability.get(s) == "starting"]
        unavail_s = [
            s for s in profile.scanners
            if scanner_availability.get(s) not in ("reachable", "starting")
        ]
        if len(avail) == len(profile.scanners):
            state = "available"
            note = ""
        elif avail:
            parts = []
            if unavail_s:
                parts.append(f"{', '.join(unavail_s)} unavailable")
            if starting_s:
                parts.append(f"{', '.join(starting_s)} still starting")
            note = (" — ".join(parts)) + " — partial scan only"
            state = "degraded"
        elif starting_s:
            state = "starting"
            note = f"Waiting for {', '.join(starting_s)} to initialize"
        else:
            state = "unavailable"
            note = f"Requires {', '.join(profile.scanners)} — none reachable"
        default_scanner = profile.scanners[0] if profile.scanners else ""
        fallback = starting_s[0] if starting_s else default_scanner
        first_avail = avail[0] if avail else fallback
        profile_capability[profile.profile_id] = {
            "state": state,
            "note": note,
            "first_available_scanner": first_avail,
        }

    target = inv.targets[0] if inv.targets else ""

    # Quick (non-blocking) target resolution for UI display — no network call
    target_ctx = None

    latest_confidence, latest_confidence_msg = (
        _scan_confidence(latest_scan) if latest_scan else ("pending", "")
    )

    # Latest run confidence + evidence count + skill count for the completion bar
    latest_run_confidence = (
        latest_run.confidence if latest_run and latest_run.is_terminal else "pending"
    )
    latest_run_confidence_msg = latest_run.confidence_message if latest_run else ""
    evidence_count = sum(len(f.evidence_refs) for f in latest_findings)

    response = templates.TemplateResponse(
        "partials/scan_orchestration_panel.html",
        {
            "request": request,
            "investigation": inv,
            "runs": runs,
            "summary": summary,
            "profiles": ALL_PROFILES,
            "scanner_availability": scanner_availability,
            "scanner_status_detail": scanner_status_detail,
            "profile_capability": profile_capability,
            "scanner_stage_labels": SCANNER_STAGE_LABELS,
            "latest_findings": latest_findings[:25],
            "latest_scan": latest_scan,
            "latest_run": latest_run,
            "latest_confidence": latest_run_confidence,
            "latest_confidence_msg": latest_run_confidence_msg,
            "evidence_count": evidence_count,
            "skills_count": skills_count,
            "target": target,
            "target_ctx": target_ctx,
        },
    )
    # Disable browser caching — every HTMX poll must hit fresh state
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@router.get(
    "/runs/{group_id}/timeline-partial",
    response_class=HTMLResponse,
)
async def run_timeline_partial(group_id: str, request: Request):
    """Aggregated execution timeline for all stages in an investigation run."""
    from apps.investigation_core.storage.timeline_repo import TimelineRepository
    from dataclasses import dataclass as _dc

    @_dc
    class InvestigationRun:
        group_id: str
        profile_id: str
        target: str
        scans: list

        @property
        def confidence(self) -> str:
            terminal = [s for s in self.scans if s.is_terminal]
            if not terminal:
                return "pending"
            return "error" if any(str(s.status) == "failed" for s in terminal) else "ok"

        @property
        def confidence_message(self) -> str:
            counts = sum(getattr(s, "findings_count", 0) for s in self.scans)
            return f"{counts} finding(s)" if counts else ""

        @property
        def is_terminal(self) -> bool:
            return bool(self.scans) and all(s.is_terminal for s in self.scans)

    async with get_db() as db:
        scan_repo = _import_scan_repo(db)
        scans = await scan_repo.list_by_group(group_id)
        if not scans:
            return HTMLResponse(
                '<span style="font-size:.72rem;color:var(--text-muted);">No stages found.</span>'
            )
        tl_repo = TimelineRepository(db)
        # Query events for each scan in the run (filtered at DB level by scan_id).
        run_events_raw = []
        inv_id = scans[0].investigation_id
        for s in scans:
            run_events_raw.extend(await tl_repo.list_for_scan(inv_id, s.scan_id, limit=50))
        # Sort chronologically across all stages
        run_events_raw.sort(key=lambda e: e.timestamp)

    scan_scanner = {s.scan_id: s.scanner_type for s in scans}

    # Annotate with stage-change markers
    prev_scanner: str | None = None
    events_annotated: list[dict] = []
    for e in run_events_raw:
        scanner = scan_scanner.get(e.detail.get("scan_id", ""), "")
        new_stage = scanner != prev_scanner
        events_annotated.append({"event": e, "scanner_type": scanner, "new_stage": new_stage})
        prev_scanner = scanner

    run = InvestigationRun(
        group_id=group_id,
        profile_id=scans[0].profile,
        target=scans[0].target,
        scans=scans,
    )
    return templates.TemplateResponse(
        "partials/run_timeline_fragment.html",
        {
            "request": request,
            "run": run,
            "events": events_annotated,
            "scanner_stage_labels": SCANNER_STAGE_LABELS,
            "confidence": run.confidence,
            "confidence_msg": run.confidence_message,
        },
    )


def _import_scan_repo(db: Any) -> Any:
    from apps.scanner_orchestration.storage.scan_repo import ScanRepository
    return ScanRepository(db)


@router.get(
    "/scans/{scan_id}/timeline-partial",
    response_class=HTMLResponse,
)
async def scan_timeline_partial(scan_id: str, request: Request):
    """Execution timeline for a single scan — rendered into the expand row on demand."""
    async with get_db() as db:
        from apps.investigation_core.storage.timeline_repo import TimelineRepository

        svc = OrchestrationService(db)
        scan = await svc.get_scan(scan_id)
        if not scan:
            return HTMLResponse(
                '<span style="font-size:.72rem;color:var(--text-muted);">Scan not found.</span>'
            )

        tl_repo = TimelineRepository(db)
        scan_events = await tl_repo.list_for_scan(scan.investigation_id, scan_id, limit=50)

    confidence, confidence_msg = _scan_confidence(scan)

    return templates.TemplateResponse(
        "partials/scan_timeline_fragment.html",
        {
            "request": request,
            "scan": scan,
            "events": scan_events,
            "confidence": confidence,
            "confidence_msg": confidence_msg,
        },
    )


@router.get(
    "/scans/{scan_id}/status-partial",
    response_class=HTMLResponse,
)
async def scan_status_partial(scan_id: str, request: Request):
    """Lightweight status fragment for HTMX polling.

    While running: includes a live checklist of timeline events (progress steps).
    When terminal: emits HX-Trigger: reload-scans so the panel refreshes automatically.
    """
    from apps.investigation_core.storage.timeline_repo import TimelineRepository

    async with get_db() as db:
        svc = OrchestrationService(db)
        scan = await svc.get_scan(scan_id)
        if not scan:
            return HTMLResponse("<span>Scan not found.</span>", status_code=404)

        # Query timeline events for THIS scan (filtered at DB level — avoids the
        # limit/ordering trap of list_for_investigation on large investigations).
        tl_repo = TimelineRepository(db)
        scan_events = await tl_repo.list_for_scan(scan.investigation_id, scan_id, limit=50)

    still_running = not scan.is_terminal
    status_str = str(scan.status)

    status_classes = {
        "queued":    "qstatus-pending",
        "running":   "qstatus-running",
        "completed": "qstatus-completed",
        "failed":    "qstatus-failed",
        "cancelled": "qstatus-rejected",
    }
    cls = status_classes.get(status_str, "qstatus-pending")

    # Investigation-centric narrative
    if status_str == "queued":
        narrative = "Preparing to launch…"
    elif status_str == "running":
        narrative = "Investigation running…"
    elif status_str == "completed":
        if scan.findings_count > 0:
            narrative = f"{scan.findings_count} finding(s)"
            if scan.error_message:
                narrative += f" · ⚠ {scan.error_message[:60]}"
        else:
            narrative = (
                f"⚠ {scan.error_message[:60]}" if scan.error_message
                else "No findings"
            )
    elif status_str == "failed":
        narrative = "Failed"
    else:
        narrative = status_str

    if scan.duration_seconds and scan.is_terminal:
        narrative += f" · {scan.duration_seconds:.0f}s"

    hx_attrs = (
        f'hx-get="/api/v1/validation/scanner/scans/{scan_id}/status-partial" '
        f'hx-trigger="every 3s" hx-swap="outerHTML"'
        if still_running else ""
    )

    # Map event types to investigation-centric step labels and icons
    _STEP_LABELS = {
        "scan_queued":          ("●", "Queued"),
        "target_resolved":      ("→", "Resolving target"),
        "target_reachable":     ("✓", "Target confirmed"),
        "target_fingerprinted": ("◉", "Service identified"),
        "target_unreachable":   ("✗", "Target unreachable"),
        "scan_started":         ("▶", "Scanning"),
        "findings_normalized":  ("✓", "Processing findings"),
        "scan_completed":       ("✓", "Complete"),
        "scan_failed":          ("✗", "Failed"),
    }
    _DONE_TYPES = {
        "target_reachable", "target_fingerprinted",
        "findings_normalized", "scan_completed",
    }
    _BAD_TYPES  = {"target_unreachable", "scan_failed"}

    badge_parts = [
        f'<span class="scan-status-fragment" {hx_attrs}>',
        f'<span class="qstatus {cls}">{scan.status}</span>',
        f'<span style="font-size:.7rem;margin-left:.35rem;font-family:var(--mono);">'
        f'{narrative}</span>',
    ]

    # Live terminal-style activity log — vertical, timestamped, with detail
    if scan_events and (still_running or len(scan_events) <= 12):
        log_html = '<div class="so-live-log"><div class="so-log-title">▍ Activity log</div>'
        for ev in scan_events:
            et = str(ev.event_type)
            icon, _ = _STEP_LABELS.get(et, ("·", ""))
            if et in _DONE_TYPES:
                col_cls = "so-log-ok"
            elif et in _BAD_TYPES:
                col_cls = "so-log-err"
            elif et == "scan_started":
                col_cls = "so-log-active"
            else:
                col_cls = "so-log-info"

            # Pull richer detail from the event's detail dict
            d = ev.detail or {}
            extra = ""
            if et == "target_resolved":
                url = d.get("scanner_url", "")
                if url:
                    extra = f' <span class="so-log-detail">→ {url}</span>'
            elif et == "target_reachable":
                fp = d.get("fingerprint")
                lat = d.get("latency_ms")
                bits = []
                if fp:
                    bits.append(fp)
                if lat:
                    bits.append(f"{lat:.0f}ms")
                if bits:
                    extra = f' <span class="so-log-detail">— {" · ".join(bits)}</span>'
            elif et == "target_fingerprinted":
                fp = d.get("fingerprint", "")
                conf = d.get("confidence", "")
                extra = f' <span class="so-log-detail">— {fp} ({conf})</span>'
            elif et == "scan_started":
                scanner = d.get("scanner_type", "")
                tgt = d.get("target", "")
                extra = f' <span class="so-log-detail">— {scanner} → {tgt}</span>'
            elif et == "findings_normalized":
                count = d.get("count", 0)
                types = d.get("finding_types", [])
                if types:
                    types_str = ", ".join(types[:4])
                    extra = (
                        f' <span class="so-log-detail">'
                        f'— {count} finding(s): {types_str}</span>'
                    )
                else:
                    extra = f' <span class="so-log-detail">— {count} finding(s)</span>'
            elif et == "scan_completed":
                count = d.get("findings_count", 0)
                dur = d.get("duration_seconds", 0) or 0
                extra = f' <span class="so-log-detail">— {count} finding(s) in {dur:.0f}s</span>'
            elif et == "scan_failed":
                err = d.get("error", "")
                if err:
                    extra = f' <span class="so-log-detail">— {str(err)[:80]}</span>'
            elif et == "target_unreachable":
                err = d.get("error", "")
                if err:
                    extra = f' <span class="so-log-detail">— {str(err)[:80]}</span>'

            ts = ev.timestamp.strftime('%H:%M:%S')
            log_html += (
                f'<div class="so-log-line {col_cls}">'
                f'<span class="so-log-ts">{ts}</span>'
                f'<span class="so-log-icon">{icon}</span>'
                f'<span class="so-log-msg">{ev.summary}{extra}</span>'
                f'</div>'
            )

        # Pulse-line showing current elapsed time during execution
        if still_running:
            elapsed = 0
            if scan.started_at:
                elapsed = (datetime.utcnow() - scan.started_at).total_seconds()
            elif scan.created_at:
                elapsed = (datetime.utcnow() - scan.created_at).total_seconds()
            log_html += (
                f'<div class="so-log-line so-log-pulse">'
                f'<span class="so-log-ts">·</span>'
                f'<span class="so-log-icon">⟳</span>'
                f'<span class="so-log-msg">{scan.scanner_type} running — '
                f'{int(elapsed)}s elapsed (refreshes every 3s)</span>'
                f'</div>'
            )
        log_html += '</div>'
        badge_parts.append(log_html)

    if status_str == "failed" and scan.error_message:
        badge_parts.append(
            f'<span style="font-size:.68rem;color:var(--critical);margin-left:.35rem;'
            f'max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">'
            f'{scan.error_message[:100]}</span>'
        )
    badge_parts.append("</span>")
    badge = "".join(badge_parts)

    response = HTMLResponse(badge)
    # Disable caching — every 3s poll must hit the backend fresh
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    # Broadcast reload-scans when terminal — ws-tab-scans listens and re-fetches.
    if not still_running:
        response.headers["HX-Trigger"] = "reload-scans"
    return response
