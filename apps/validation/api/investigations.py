"""Investigations router — aggregated per-target investigation workflow view.

An investigation is a stateful view of everything that has happened to a
specific scan target: discovery, detection, validation, findings, and
knowledge export. It derives its stage from existing data — no new tables.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from apps.validation.database import get_db
from apps.validation.repositories import (
    AssetRepository,
    ChangeRepository,
    FindingRepository,
    HistoryRepository,
    HostRepository,
    QueueRepository,
)

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


def _compute_js_ver() -> str:
    """SHA-1 of the two mutable JS assets, truncated to 8 hex chars.

    Computed once at import time so there is no per-request cost.
    Changes automatically whenever workspace.js or exploitation-mindmap.js
    is modified, giving browsers a fresh cache key after every deployment.
    """
    import hashlib
    from pathlib import Path
    _js = Path(__file__).resolve().parents[3] / "frontend" / "static" / "js"
    digest = hashlib.sha1()
    for name in ("workspace.js", "exploitation-mindmap.js"):
        try:
            digest.update((_js / name).read_bytes())
        except OSError:
            digest.update(name.encode())
    return digest.hexdigest()[:8]


_JS_VER: str = _compute_js_ver()


# ---------------------------------------------------------------------------
# Stage model
# ---------------------------------------------------------------------------

# Ordered stages for the workflow timeline
PIPELINE_STAGES = [
    ("discovered",  "Discovery"),
    ("detection",   "Detection"),
    ("validation",  "Validation"),
    ("findings",    "Findings"),
    ("learning",    "Learning"),
]


@dataclass
class TimelineStage:
    key: str
    label: str
    state: str  # done | active | warn | critical | pending
    count: int = 0


@dataclass
class InvestigationSummary:
    target: str
    asset_name: str
    asset_id: str | None
    stage: str              # machine-readable stage key
    stage_label: str        # human-readable label
    last_activity: str      # human-readable "X ago" or ISO date
    last_activity_raw: str  # ISO string for sorting
    findings_critical: int
    findings_high: int
    findings_medium: int
    findings_low: int
    exploitable_count: int
    pending_validations: int
    total_findings: int
    next_action: str
    next_action_url: str
    next_action_type: str   # primary | warn | critical | info
    workspace_url: str = ""  # URL to per-target investigation workspace
    # When non-None, the card shows a delete control bound to this id.
    # Populated for cards backed by investigation_core.investigations.
    investigation_id: str | None = None
    timeline: list[TimelineStage] = field(default_factory=list)
    recent_events: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Stage derivation
# ---------------------------------------------------------------------------


def _workspace_url(target: str) -> str:
    """Build the investigation workspace URL for a target."""
    return f"/api/v1/validation/investigations/workspace?target={quote(target, safe='')}"


def _derive_stage(
    has_scan: bool,
    has_hosts: bool,
    has_queue: bool,
    has_pending: bool,
    has_findings: bool,
    has_exploitable: bool,
    target: str = "",
) -> tuple[str, str, str, str, str]:
    """Return (stage_key, stage_label, next_action, next_action_url, action_type).

    All next_action_urls now route into the investigation workspace so the
    user stays within the investigation context.
    """
    ws = _workspace_url(target) if target else "/api/v1/validation/investigations"
    if not has_scan:
        return (
            "no_scan", "Not Scanned",
            "Start Investigation", ws, "primary",
        )
    if not has_hosts:
        return (
            "discovered", "No Hosts Found",
            "Rescan Target", ws, "info",
        )
    if not has_queue and not has_findings:
        return (
            "detection", "Services Detected",
            "Review Validation", f"{ws}#validation", "primary",
        )
    if has_pending:
        return (
            "validation", "Validation Pending",
            "Approve Validations", f"{ws}#validation", "warn",
        )
    if has_exploitable:
        return (
            "confirmed", "Vulnerabilities Confirmed",
            "Review Findings", f"{ws}#findings", "critical",
        )
    if has_findings:
        return (
            "findings", "Tested — Review Findings",
            "Review Findings", f"{ws}#findings", "info",
        )
    return (
        "clear", "No Issues Found",
        "Run Follow-up Scan", ws, "info",
    )


def _build_timeline(stage: str, exploitable: bool, pending: int) -> list[TimelineStage]:
    """Build ordered timeline stages with state for the current investigation stage."""
    # Map stage keys to their position in the pipeline
    # Handle derived stages that map to pipeline positions
    stage_to_pos = {
        "no_scan": -1,
        "discovered": 0,
        "detection": 1,
        "validation": 2,
        "confirmed": 3,
        "findings": 3,
        "clear": 3,
        "learning": 4,
        "exported": 4,
    }
    active_pos = stage_to_pos.get(stage, -1)

    result: list[TimelineStage] = []
    for i, (key, label) in enumerate(PIPELINE_STAGES):
        if i < active_pos:
            state = "done"
        elif i == active_pos:
            if stage == "confirmed" or exploitable:
                state = "critical"
            elif pending > 0 and key == "validation":
                state = "warn"
            else:
                state = "active"
        else:
            state = "pending"
        result.append(TimelineStage(key=key, label=label, state=state))
    return result


def _humanize_dt(dt: datetime | None) -> str:
    if dt is None:
        return "never"
    now = datetime.utcnow().replace(tzinfo=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    diff = now - dt
    if diff.total_seconds() < 60:
        return "just now"
    if diff.total_seconds() < 3600:
        m = int(diff.total_seconds() / 60)
        return f"{m}m ago"
    if diff.total_seconds() < 86400:
        h = int(diff.total_seconds() / 3600)
        return f"{h}h ago"
    d = diff.days
    return f"{d}d ago"


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.get("/investigations", response_class=HTMLResponse)
async def investigations_page(request: Request):
    """Primary workflow page — one card per configured asset (or per discovered host
    if no assets are configured). Shows investigation stage, severity summary, and
    recommended next action."""

    async with get_db() as db:
        asset_repo   = AssetRepository(db)
        host_repo    = HostRepository(db)
        finding_repo = FindingRepository(db)
        queue_repo   = QueueRepository(db)
        change_repo  = ChangeRepository(db)
        history_repo = HistoryRepository(db)

        assets = await asset_repo.list_all()
        all_hosts = await host_repo.list_all()
        all_findings = await finding_repo.list_all(limit=10_000)
        all_queue = await queue_repo.list_all(limit=10_000)
        all_changes = await change_repo.list_unacknowledged()
        recent_history = await history_repo.list_all(limit=20)
        queue_counts = await queue_repo.count_by_status()

    # Build IP → host lookup
    ip_to_host: dict[str, Any] = {h.ip: h for h in all_hosts}

    # Build host_id → findings list
    findings_by_host: dict[str, list[Any]] = {}
    for f in all_findings:
        findings_by_host.setdefault(f.host_id, []).append(f)

    # Build host_id → queue items list
    queue_by_host: dict[str, list[Any]] = {}
    for q in all_queue:
        queue_by_host.setdefault(q.host_id, []).append(q)

    # Derive investigations per asset
    investigations: list[InvestigationSummary] = []

    if assets:
        # Asset-based view (preferred)
        for asset in assets:
            host = ip_to_host.get(asset.target)
            host_id = host.id if host else None

            has_scan = asset.last_scanned_at is not None
            has_hosts = host is not None

            host_findings = findings_by_host.get(host_id, []) if host_id else []
            host_queue    = queue_by_host.get(host_id, []) if host_id else []

            has_queue    = len(host_queue) > 0
            has_pending  = any(q.status in ("pending", "approved") for q in host_queue)
            has_findings = len(host_findings) > 0
            exploitable = [
                f for f in host_findings
                if f.validation_status == "validated_exploitable"
            ]
            has_exploitable = len(exploitable) > 0

            sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in host_findings:
                sev[f.severity.value] = sev.get(f.severity.value, 0) + 1

            pending_count = sum(1 for q in host_queue if q.status in ("pending", "approved"))

            stage, stage_label, next_action, next_url, action_type = _derive_stage(
                has_scan, has_hosts, has_queue, has_pending,
                has_findings, has_exploitable, target=asset.target,
            )

            # Last activity: most recent finding or scan timestamp
            ts_candidates: list[datetime] = []
            if asset.last_scanned_at:
                ts_candidates.append(asset.last_scanned_at)
            for f in host_findings:
                ts_candidates.append(f.timestamp)
            last_ts = max(ts_candidates) if ts_candidates else None

            timeline = _build_timeline(stage, has_exploitable, pending_count)

            inv = InvestigationSummary(
                target=asset.target,
                asset_name=asset.name,
                asset_id=asset.id,
                stage=stage,
                stage_label=stage_label,
                last_activity=_humanize_dt(last_ts),
                last_activity_raw=last_ts.isoformat() if last_ts else "",
                findings_critical=sev.get("critical", 0),
                findings_high=sev.get("high", 0),
                findings_medium=sev.get("medium", 0),
                findings_low=sev.get("low", 0),
                exploitable_count=len(exploitable),
                pending_validations=pending_count,
                total_findings=len(host_findings),
                next_action=next_action,
                next_action_url=next_url,
                next_action_type=action_type,
                workspace_url=_workspace_url(asset.target),
                timeline=timeline,
                recent_events=[],
            )
            investigations.append(inv)
    else:
        # No assets configured — fall back to per-host view
        for host in all_hosts:
            host_findings = findings_by_host.get(host.id, [])
            host_queue    = queue_by_host.get(host.id, [])

            has_queue    = len(host_queue) > 0
            has_pending  = any(q.status in ("pending", "approved") for q in host_queue)
            has_findings = len(host_findings) > 0
            exploitable = [
                f for f in host_findings
                if f.validation_status == "validated_exploitable"
            ]
            has_exploitable = len(exploitable) > 0

            sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in host_findings:
                sev[f.severity.value] = sev.get(f.severity.value, 0) + 1

            pending_count = sum(1 for q in host_queue if q.status in ("pending", "approved"))

            stage, stage_label, next_action, next_url, action_type = _derive_stage(
                True, True, has_queue, has_pending,
                has_findings, has_exploitable, target=host.ip,
            )

            ts_candidates = [host.last_seen] + [f.timestamp for f in host_findings]
            last_ts = max(ts_candidates) if ts_candidates else None

            timeline = _build_timeline(stage, has_exploitable, pending_count)

            inv = InvestigationSummary(
                target=host.ip,
                asset_name=host.hostname or host.ip,
                asset_id=None,
                stage=stage,
                stage_label=stage_label,
                last_activity=_humanize_dt(last_ts),
                last_activity_raw=last_ts.isoformat() if last_ts else "",
                findings_critical=sev.get("critical", 0),
                findings_high=sev.get("high", 0),
                findings_medium=sev.get("medium", 0),
                findings_low=sev.get("low", 0),
                exploitable_count=len(exploitable),
                pending_validations=pending_count,
                total_findings=len(host_findings),
                next_action=next_action,
                next_action_url=next_url,
                next_action_type=action_type,
                workspace_url=_workspace_url(host.ip),
                timeline=timeline,
                recent_events=[],
            )
            investigations.append(inv)

    # ── Orchestration investigations not covered by legacy assets/hosts ──
    # New scans (POST /runs) create records in investigation_core.investigations
    # + scan_executions + normalized_findings. These are NOT in the legacy
    # assets/hosts/findings tables — add them as cards here.
    covered = {inv.target for inv in investigations}
    async with get_db() as db:
        from apps.investigation_core.services.investigation_service import (
            InvestigationService as _InvCoreSvc,
        )
        from apps.scanner_orchestration.services.orchestration_service import (
            OrchestrationService as _OrchSvc,
        )
        inv_core_svc = _InvCoreSvc(db)
        orch_svc = _OrchSvc(db)
        all_core_invs = await inv_core_svc.list_all(limit=200)

        # Back-fill investigation_id onto legacy summaries whose target
        # matches a core investigation, so the delete control can appear
        # on every card backed by a deletable record.
        target_to_iid: dict[str, str] = {}
        for ci in all_core_invs:
            for t in (ci.targets or []):
                target_to_iid.setdefault(t, ci.investigation_id)
        for legacy_inv in investigations:
            if legacy_inv.investigation_id is None:
                legacy_inv.investigation_id = target_to_iid.get(legacy_inv.target)

        for core_inv in all_core_invs:
            if not core_inv.targets:
                continue
            target = core_inv.targets[0]
            if target in covered:
                continue

            runs = await orch_svc.list_runs(core_inv.investigation_id, limit=10)
            all_orch_scans = [s for r in runs for s in r.scans]

            orch_findings = []
            if runs:
                latest = runs[0]
                if latest.group_id:
                    orch_findings = await orch_svc.list_run_findings(latest.group_id)
                elif latest.scans:
                    completed = [s for s in latest.scans if str(s.status) == "completed"]
                    if completed:
                        orch_findings = await orch_svc.list_findings(completed[0].scan_id)

            sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in orch_findings:
                if f.severity in sev:
                    sev[f.severity] += 1

            has_scan = bool(runs)
            has_findings = bool(orch_findings)
            stage, stage_label, next_action, next_url, action_type = _derive_stage(
                has_scan=has_scan, has_hosts=has_scan,
                has_queue=False, has_pending=False,
                has_findings=has_findings, has_exploitable=False,
                target=target,
            )
            ts_cands = [
                s.completed_at or s.started_at or s.created_at
                for s in all_orch_scans
            ]
            ts_cands = [t for t in ts_cands if t]
            # Normalize to offset-aware UTC before comparing to avoid
            # TypeError when mixing naive and aware datetimes across sources.
            from datetime import timezone as _tz
            def _to_utc(dt):
                if dt is None:
                    return None
                if hasattr(dt, 'tzinfo') and dt.tzinfo is not None:
                    return dt
                return dt.replace(tzinfo=_tz.utc)
            ts_cands = [_to_utc(t) for t in ts_cands if t]
            last_ts = max(ts_cands) if ts_cands else None
            timeline = _build_timeline(stage, False, 0)

            investigations.append(InvestigationSummary(
                target=target,
                asset_name=core_inv.title or target,
                asset_id=None,
                stage=stage,
                stage_label=stage_label,
                last_activity=_humanize_dt(last_ts),
                last_activity_raw=last_ts.isoformat() if last_ts else "",
                findings_critical=sev["critical"],
                findings_high=sev["high"],
                findings_medium=sev["medium"],
                findings_low=sev["low"],
                exploitable_count=0,
                pending_validations=0,
                total_findings=len(orch_findings),
                next_action=next_action,
                next_action_url=next_url,
                next_action_type=action_type,
                workspace_url=_workspace_url(target),
                investigation_id=core_inv.investigation_id,
                timeline=timeline,
                recent_events=[],
            ))

    # Sort: critical confirmed first, then by pending, then by last activity desc
    def _sort_key(inv: InvestigationSummary) -> tuple:
        critical = inv.stage == "confirmed" and inv.findings_critical > 0
        return (
            0 if critical else 1,
            0 if inv.pending_validations > 0 else 1,
            -(inv.findings_critical * 100 + inv.findings_high * 10 + inv.findings_medium),
            inv.last_activity_raw,  # earlier = lower priority (descending by recent)
        )

    investigations.sort(key=_sort_key)

    # Dashboard summary numbers
    confirmed_count   = sum(1 for i in investigations if i.stage == "confirmed")
    pending_total     = sum(i.pending_validations for i in investigations)
    critical_findings = sum(i.findings_critical for i in investigations)
    no_scan_count     = sum(1 for i in investigations if i.stage == "no_scan")

    # Recent events from history
    events = recent_history[:8]

    # Queue count for nav badge
    queue_count = queue_counts.get("pending", 0)
    unacked_changes = len(all_changes)

    return templates.TemplateResponse(
        "investigations.html",
        {
            "request": request,
            "active": "investigations",
            "investigations": investigations,
            "confirmed_count": confirmed_count,
            "pending_total": pending_total,
            "critical_findings": critical_findings,
            "no_scan_count": no_scan_count,
            "total_investigations": len(investigations),
            "events": events,
            "queue_count": queue_count,
            "unacked_changes": unacked_changes,
            "has_assets": bool(assets),
        },
    )


# ---------------------------------------------------------------------------
# Per-target investigation workspace
# ---------------------------------------------------------------------------


@router.post("/investigations/{investigation_id}/delete")
async def delete_investigation(investigation_id: str) -> JSONResponse:
    """Hard-delete an investigation and FULLY tear it down.

    Order of operations:
    1. Cancel any in-flight autonomous task (immediate, not graceful).
    2. Clear _running_tasks so a new investigation is NOT blocked by stale run-state.
    3. Delete exploitation_branches for this investigation.
    4. Delete orphan exploitation_branches (investigation_id='' or NULL).
    5. Cascade-delete all other rows via InvestigationRepository.delete().

    Destructive and irreversible. The frontend confirms with the operator
    before issuing this call.
    """
    import logging as _logging
    _del_log = _logging.getLogger("investigations.delete")

    from apps.investigation_core.storage.investigation_repo import (
        InvestigationRepository,
    )
    from apps.validation.database import get_db as _get_val_db

    # ── Step 1 & 2: cancel in-flight autonomous task + clear run-state ────────
    try:
        from apps.conductor.autonomous_orchestrator import request_stop, _running_tasks
        # request_stop sets the stop flag AND calls task.cancel() immediately
        await request_stop(investigation_id)
        # Also forcibly remove from the registry so is_running() returns False
        _running_tasks.pop(investigation_id, None)
        _del_log.info("delete: cancelled autonomous task for %s", investigation_id)
    except Exception as _e:
        _del_log.warning("delete: autonomous stop failed (non-fatal): %s", _e)

    # Also cancel conductor context if present
    try:
        from apps.conductor.shared import get_shared_conductor
        _conductor = get_shared_conductor()
        _ctx = _conductor.get_context(investigation_id)
        if _ctx is not None:
            await _ctx.exec_orch.cancel_all()
            _conductor._active.pop(investigation_id, None)
            _del_log.info("delete: cancelled executor context for %s", investigation_id)
    except Exception as _e:
        _del_log.warning("delete: executor cancel failed (non-fatal): %s", _e)

    # ── Steps 3 & 4: delete branches + per-investigation stores ─────────────
    try:
        async with _get_val_db() as _vdb:
            _r1 = await _vdb.execute(
                "DELETE FROM exploitation_branches WHERE investigation_id = ?",
                (investigation_id,),
            )
            _r2 = await _vdb.execute(
                "DELETE FROM exploitation_branches WHERE investigation_id = '' OR investigation_id IS NULL",
            )
            # Part 3: delete chat history (must not orphan on investigation delete)
            _r3 = await _vdb.execute(
                "DELETE FROM investigation_chat_history WHERE investigation_id = ?",
                (investigation_id,),
            )
            # Also clean up any unknown artifacts for this investigation
            _r4 = await _vdb.execute(
                "DELETE FROM agent_loop_unknowns WHERE investigation_id = ?",
                (investigation_id,),
            )
            await _vdb.commit()
            _del_log.info(
                "delete: removed %d branch(es) for %s + %d orphan(s) + %d chat(s) + %d unknown(s)",
                _r1.rowcount, investigation_id, _r2.rowcount, _r3.rowcount, _r4.rowcount,
            )
    except Exception as _e:
        _del_log.warning("delete: branch cleanup failed (non-fatal): %s", _e)

    # ── Step 5: cascade-delete investigation rows ─────────────────────────────
    async with get_db() as db:
        repo = InvestigationRepository(db)
        deleted = await repo.delete(investigation_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return JSONResponse(content={"deleted": True, "investigation_id": investigation_id})


async def _persist_self_login(
    investigation_id: str,
    target: str,
    provided_self_user: str,
    self_pass: str,  # SENSITIVE — never log, never include in responses or audit trails
) -> None:
    """Persist self-login params into agent_state at investigation creation time.

    provided_self_user → agent_state.goal.provided_self_user (same field the chat path uses)
    self_pass          → agent_state.operator_params.self_pass (write-only; not returned by any route)

    TODO: encrypt agent_state.operator_params.self_pass at rest before productization.
    """
    import logging as _log
    _ps_logger = _log.getLogger(__name__)
    try:
        from apps.conductor.agent_state import (
            get_or_init_agent_state_async,
            save_agent_state_async,
            _get_state_lock,
        )
        lock = _get_state_lock(investigation_id)
        async with lock:
            state = await get_or_init_agent_state_async(investigation_id, target=target)
            if "goal" in state:
                state["goal"]["provided_self_user"] = provided_self_user
            op = state.setdefault("operator_params", {})
            op["provided_self_user"] = provided_self_user
            op["self_pass"] = self_pass   # SENSITIVE: write-only, never logged
            await save_agent_state_async(investigation_id, state)
    except Exception as exc:
        # Log investigation_id only — never log self_pass or provided_self_user values
        _ps_logger.warning("_persist_self_login(%s): failed — %s", investigation_id, exc)


@router.post("/investigations/start")
async def start_investigation_post(request: Request):
    """Create or fetch an investigation and optionally persist self-login operator params.

    Request body: {target, environment?, provided_self_user?, self_pass?}
    Returns JSON: {workspace_url, investigation_id, provided_self_user}

    Security:
      - self_pass is NEVER echoed in the response.
      - self_pass is NEVER logged (not in request logs, error messages, or debug output).
      - provided_self_user and self_pass must be supplied together or both omitted.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    target = (body.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")

    provided_self_user = (body.get("provided_self_user") or "").strip()
    # self_pass is SENSITIVE — never log this value
    _self_pass = (body.get("self_pass") or "").strip()

    # Pair-completeness validation: both fields must be supplied together or both omitted
    if bool(provided_self_user) != bool(_self_pass):
        raise HTTPException(
            status_code=400,
            detail="Both provided_self_user and self_pass must be supplied together, or both omitted.",
        )

    from apps.investigation_core.services.investigation_service import (
        InvestigationService as _StartInvSvc,
    )

    async with get_db() as db:
        inv, _ = await _StartInvSvc(db).get_or_create(
            target, title=f"Investigation: {target}"
        )
        investigation_id = inv.investigation_id

    if provided_self_user:
        await _persist_self_login(investigation_id, target, provided_self_user, _self_pass)

    return JSONResponse(content={
        "workspace_url":      f"/api/v1/validation/investigations/workspace?target={quote(target, safe='')}",
        "investigation_id":   investigation_id,
        "provided_self_user": provided_self_user or None,
        # self_pass intentionally omitted from response
    })


@router.get("/investigations/workspace", response_class=HTMLResponse)
async def investigation_workspace(request: Request, target: str = Query(...)):
    """Single-target investigation workspace.

    Embeds the full investigation workflow for one target: scan control,
    discovered hosts, validation queue items, and findings — all without
    leaving the investigation context.
    """
    async with get_db() as db:
        host_repo    = HostRepository(db)
        finding_repo = FindingRepository(db)
        queue_repo   = QueueRepository(db)
        asset_repo   = AssetRepository(db)
        change_repo  = ChangeRepository(db)

        all_hosts    = await host_repo.list_all()
        all_findings = await finding_repo.list_all(limit=10_000)
        all_queue    = await queue_repo.list_all(limit=10_000)
        assets       = await asset_repo.list_all()
        all_changes  = await change_repo.list_unacknowledged()
        queue_counts = await queue_repo.count_by_status()

    # Find the host matching the target IP
    host = next((h for h in all_hosts if h.ip == target), None)

    # Find asset for this target
    asset = next((a for a in assets if a.target == target), None)
    asset_name = asset.name if asset else (host.hostname if host else target)

    # Filter findings and queue to this host only
    host_id = host.id if host else None
    host_findings = [f for f in all_findings if f.host_id == host_id] if host_id else []
    host_queue    = [q for q in all_queue    if q.host_id == host_id] if host_id else []

    # Enrich findings with service info
    from apps.validation.database import get_db as _get_db
    async with _get_db() as db:
        from apps.validation.repositories import CVERepository, ServiceRepository
        svc_repo = ServiceRepository(db)
        cve_repo = CVERepository(db)
        for f in host_findings:
            if f.service_id:
                f.service = await svc_repo.get_by_id(f.service_id)
            if f.cve_id:
                f.cve = await cve_repo.get_by_id(f.cve_id)
            f.host = host

        # Enrich queue items
        for q in host_queue:
            if q.service_id:
                q.service = await svc_repo.get_by_id(q.service_id)
            if q.cve_id:
                q.cve = await cve_repo.get_by_id(q.cve_id)
            q.host = host

        # Services for this host
        host_services = await svc_repo.list_by_host(host_id) if host_id else []

    # Derive investigation state
    has_scan     = asset.last_scanned_at is not None if asset else host is not None
    has_hosts    = host is not None
    has_queue_   = len(host_queue) > 0
    has_pending  = any(q.status in ("pending", "approved") for q in host_queue)
    has_findings = len(host_findings) > 0
    exploitable  = [f for f in host_findings if f.validation_status == "validated_exploitable"]
    has_exploitable = len(exploitable) > 0

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in host_findings:
        sev[f.severity.value] = sev.get(f.severity.value, 0) + 1

    pending_count = sum(1 for q in host_queue if q.status in ("pending", "approved"))

    stage, stage_label, next_action, _next_url, action_type = _derive_stage(
        has_scan, has_hosts, has_queue_, has_pending,
        has_findings, has_exploitable, target=target,
    )
    timeline = _build_timeline(stage, has_exploitable, pending_count)

    last_ts: datetime | None = None
    ts_cands = []
    if asset and asset.last_scanned_at:
        ts_cands.append(asset.last_scanned_at)
    if host:
        ts_cands.append(host.last_seen)
    ts_cands.extend(f.timestamp for f in host_findings)
    if ts_cands:
        last_ts = max(ts_cands)

    from apps.investigation_core.services.investigation_service import (
        InvestigationService as _InvCoreSvc,
    )
    from apps.validation.config import get_default_workers

    queue_count     = queue_counts.get("pending", 0)
    unacked_changes = len(all_changes)

    # Pending and recent queue items (limit to 10 each for workspace view)
    pending_items   = [q for q in host_queue if q.status in ("pending", "approved")][:10]
    recent_items    = [q for q in host_queue if q.status not in ("pending", "approved")][:5]

    # Most critical finding type for context-aware CyberLab URL
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        host_findings,
        key=lambda f: _sev_rank.get(f.severity.value, 5),
    )
    top_finding_type = (
        sorted_findings[0].finding_type.lower().replace("_", "-")
        if sorted_findings else ""
    )
    top_finding_severity = (
        sorted_findings[0].severity.value if sorted_findings else ""
    )

    # Get or create investigation_core record for this target (lazy sync).
    investigation_id: str | None = None
    async with get_db() as db:
        core_svc = _InvCoreSvc(db)
        inv, _ = await core_svc.get_or_create(target, title=f"Investigation: {asset_name}")
        investigation_id = inv.investigation_id
        # Sync any findings not yet recorded in the timeline.
        for f in host_findings:
            if f.id not in inv.findings:
                await core_svc.record_finding_detected(
                    investigation_id,
                    f.id,
                    f.finding_type,
                    f.severity.value,
                )

    # Orchestration-level metrics for the Overview tab (live, cross-context read)
    orch_findings_count = 0
    orch_evidence_count = 0
    orch_skills_count = 0
    latest_orch_run = None
    if investigation_id:
        async with get_db() as db:
            from apps.investigation_core.evidence.storage.artifact_repo import (
                ArtifactRepository as _ArtRepo,
            )
            from apps.investigation_core.progression.storage.mastery_repo import (
                MasteryRepository as _MasteryRepo,
            )
            from apps.scanner_orchestration.services.orchestration_service import (
                OrchestrationService as _OrchSvc,
            )
            orch_svc = _OrchSvc(db)
            orch_runs = await orch_svc.list_runs(investigation_id, limit=1)
            latest_orch_run = orch_runs[0] if orch_runs else None
            if latest_orch_run:
                completed_scans = [
                    s for s in latest_orch_run.scans if str(s.status) == "completed"
                ]
                if completed_scans:
                    if latest_orch_run.group_id:
                        orch_findings = await orch_svc.list_run_findings(
                            latest_orch_run.group_id
                        )
                    else:
                        orch_findings = await orch_svc.list_findings(
                            completed_scans[0].scan_id
                        )
                    orch_findings_count = len(orch_findings)
            art_repo = _ArtRepo(db)
            orch_evidence_count = await art_repo.count_for_investigation(investigation_id)
            mastery_repo = _MasteryRepo(db)
            mastery = await mastery_repo.list_for_investigation(investigation_id)
            orch_skills_count = sum(
                1 for m in mastery
                if str(m.status) in ("in_progress", "completed", "mastered")
            )

    # ── Re-derive stage with orchestration data merged in ───────────────
    # The legacy stage logic only sees assets/hosts/findings.  If we have
    # orchestration findings the stage should reflect that — not 'no_scan'.
    if latest_orch_run is not None or orch_findings_count > 0:
        has_scan_merged = has_scan or (latest_orch_run is not None)
        has_findings_merged = has_findings or orch_findings_count > 0
        stage, stage_label, next_action, _next_url, action_type = _derive_stage(
            has_scan_merged, has_scan_merged,  # treat any scan as having "host" context
            has_queue_, has_pending,
            has_findings_merged, has_exploitable,
            target=target,
        )
        timeline = _build_timeline(stage, has_exploitable, pending_count)

    # V1.4a — build stage-card data for the tabbed workspace template.
    workspace_data: dict = {"categories": [], "default_tab": "recon",
                            "is_bootstrap_running": False, "has_active_execution": False}
    if investigation_id:
        try:
            from apps.investigation_workspace.api.routes import (
                _build_workspace_data,
            )
            from apps.investigation_workspace.bootstrap.runtime import (
                get_run as get_bootstrap_run,
            )
            from apps.investigation_workspace.branch.assembler import BranchAssembler
            from apps.investigation_workspace.branch.topology_v2 import serialize_topology
            from apps.scanner_orchestration.storage.finding_repo import (
                NormalizedFindingRepository,
            )
            async with get_db() as db:
                _view = await BranchAssembler(db).assemble(investigation_id, target)
            _topo  = serialize_topology(_view)
            _brun  = get_bootstrap_run(investigation_id)
            _phase_map: dict[str, str] = {}
            _findings_by_id: dict[str, dict] = {}
            async with get_db() as _db:
                _findings = await NormalizedFindingRepository(_db).list_for_investigation(
                    investigation_id
                )
                for _f in _findings:
                    _raw = _f.raw_data or {}
                    if isinstance(_raw, dict):
                        _p = _raw.get("_phase")
                        if _p:
                            _phase_map[_f.finding_id] = _p
                    _findings_by_id[_f.finding_id] = {
                        "finding_id":   _f.finding_id,
                        "finding_type": _f.finding_type,
                        "title":        _f.title,
                        "description":  _f.description,
                        "severity":     _f.severity,
                        "endpoint":     _f.endpoint or "",
                        "raw_data":     _raw if isinstance(_raw, dict) else {},
                    }
            workspace_data = _build_workspace_data(
                _topo, _brun, investigation_id, target, _phase_map, _findings_by_id,
            )
        except Exception:
            pass  # template falls back to JS polling

    initial_branches: dict = {}
    if investigation_id:
        try:
            from apps.conductor.exploitation.branch_store import BranchReader
            _br = BranchReader()
            _branch_records = await _br.list_for_investigation(investigation_id)
            initial_branches = {
                r.branch_id: {
                    "branch_id":         r.branch_id,
                    "finding_id":        r.finding_id,
                    "engine_id":         r.engine_id,
                    "technique_class":   r.technique_class,
                    "state":             r.state,
                    "operator_params":   r.operator_params,
                    "artifact":          r.artifact,
                    "artifact_type":     r.artifact_type,
                    "exhaustion_record": r.exhaustion_record,
                    "stage_log":         r.stage_log,
                    "created_at":        r.created_at,
                    "updated_at":        r.updated_at,
                }
                for r in _branch_records
            }
        except Exception:
            initial_branches = {}

    return templates.TemplateResponse(
        "investigation_workspace.html",
        {
            "request":        request,
            "active":         "investigations",
            "target":         target,
            "active_phase":   request.query_params.get("phase", "recon"),
            "asset_name":     asset_name,
            "asset":          asset,
            "host":           host,
            "stage":          stage,
            "stage_label":    stage_label,
            "timeline":       timeline,
            "next_action":    next_action,
            "next_action_type": action_type,
            "last_activity":  _humanize_dt(last_ts),
            "findings_critical": sev.get("critical", 0),
            "findings_high":     sev.get("high", 0),
            "findings_medium":   sev.get("medium", 0),
            "findings_low":      sev.get("low", 0),
            "exploitable_count": len(exploitable),
            "pending_validations": pending_count,
            "total_findings":    len(host_findings),
            "host_findings":     host_findings,
            "host_services":     host_services,
            "pending_items":     pending_items,
            "recent_items":      recent_items,
            "default_workers":   get_default_workers(),
            "queue_count":           queue_count,
            "unacked_changes":       unacked_changes,
            "top_finding_type":      top_finding_type,
            "top_finding_severity":  top_finding_severity,
            "investigation_id":      investigation_id,
            "orch_findings_count":   orch_findings_count,
            "orch_evidence_count":   orch_evidence_count,
            "orch_skills_count":     orch_skills_count,
            "latest_orch_run":       latest_orch_run,
            "workspace_data":        workspace_data,
            "initial_branches":      initial_branches,
            "js_ver":                _JS_VER,
        },
    )
