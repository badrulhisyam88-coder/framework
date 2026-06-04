"""Investigation Workspace API — operator-facing routes.

After Phase 37, the operator UX is a React Flow execution topology. This
module mounts:

  /branches/flow/partial            React Flow mount shell (Phase 37)
  /branches/topology.json           Topology nodes + edges JSON (Phase 37)
  /context-panel/{node_id}          Right-side context panel HTML (Phase 37)
  /branch-action/{aid}/complete     Mark complete POST
  /branch-action/{aid}/capture-snapshot
  /branch-action/{aid}/mark-regression
  /evidence/capture/form            Quick-capture form (Phase 28+31)
  /evidence/capture                 Capture POST with server-side type inference
  /posture-snapshots/* + /compare-partial   Defensive posture (Phase 17)
  /comparison/partial               Cross-investigation theme comparison (Phase 15)
  /backfill-evidence-refs           Maintenance endpoint

Removed in Phase 37: branch_action_card.html + branch_lineage_inspector.html
(replaced by the unified context_panel.html); _render_action_card helper;
GET .../card endpoint (operator opens the panel via Expand).
"""

from __future__ import annotations

import json
import logging as _routes_logging
import os
import re
from uuid import uuid4

from fastapi import APIRouter, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from apps.investigation_workspace.aggregations import _build_aggregations
from apps.validation.database import get_db

router = APIRouter(prefix="/workspace", tags=["investigation-workspace"])
templates = Jinja2Templates(directory="frontend/templates")


# ── Phase 28 — deterministic artifact-type inference ────────────────────────
# Used by /evidence/capture when the operator submits via the lightweight
# quick-capture form (no manual type select). Pure regex/string matching;
# no LLM. Each branch returns the first matching ArtifactType.


def infer_artifact_type(content: str):
    """Best-effort deterministic guess at the artifact type from raw content."""
    import re

    from apps.investigation_core.evidence.models.artifact import ArtifactType

    text = (content or "").strip()
    if not text:
        return ArtifactType.NOTE

    first_line = text.splitlines()[0].strip()
    lower = text.lower()

    # HTTP response — starts with status line OR contains response headers
    if first_line.startswith(("HTTP/", "http/")):
        return ArtifactType.HTTP_RESPONSE
    if "set-cookie:" in lower or "content-type:" in lower:
        return ArtifactType.HTTP_RESPONSE

    # HTTP request — METHOD path HTTP/...
    method_match = re.match(
        r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+\S+\s+HTTP/", first_line,
    )
    if method_match:
        return ArtifactType.HTTP_REQUEST

    # Credentials — username/password pattern
    if re.search(r"(?im)^\s*(user(name)?|login|password|pass)\s*[:=]", text):
        return ArtifactType.EXTRACTED_CREDENTIAL

    # Payload markers
    payload_signals = (
        "<script", "</script>",
        "union select", "' or 1", "' or '1'='1",
        "1=1--", "1=1#", "../", "%2e%2e",
        "javascript:", "onerror=", "onload=",
    )
    if any(s in lower for s in payload_signals):
        return ArtifactType.PAYLOAD_ATTEMPT

    # Terminal output — common scanner markers or shell prompts
    if any(m in text for m in ("[+]", "[-]", "[*]", "[!]", "[i]")):
        return ArtifactType.TERMINAL_OUTPUT
    if re.match(r"^\s*[$#]\s+\S", first_line):
        return ArtifactType.TERMINAL_OUTPUT

    return ArtifactType.NOTE


def _derive_title_from_content(content: str) -> str:
    """First non-empty line, truncated to 80 chars. Empty string if no content."""
    for line in (content or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:80]
    return ""


# ── Maintenance auth helper ────────────────────────────────────────────────

def _check_maintenance_key(x_maintenance_key: str | None) -> None:
    """If MAINTENANCE_API_KEY env var is set, enforce it on the request.

    If the env var is unset the check is a no-op (local/dev compat).
    Returns None on success; raises HTTP 401 on failure.
    """
    required = os.environ.get("MAINTENANCE_API_KEY", "")
    if not required:
        return  # not configured — allow (dev environment)
    if x_maintenance_key != required:
        raise HTTPException(
            status_code=401,
            detail=(
                "Maintenance endpoint requires a valid X-Maintenance-Key header. "
                "Set MAINTENANCE_API_KEY environment variable to configure."
            ),
        )


# ── Investigation flow shell (Phase 37 — React Flow mount) ──────────────


@router.get(
    "/investigations/{investigation_id}/branches/flow/partial",
    response_class=HTMLResponse,
)
async def branch_flow_partial(
    investigation_id: str, request: Request, active: str = "",
):
    """Phase 37: returns the React Flow mount shell + context-panel container.

    The actual topology nodes/edges are fetched by the JS module from
    /branches/topology.json. This route just delivers the HTML shell with
    the right data-investigation-id, the Tailwind Play CDN script tag, and
    the React Flow stylesheet link. The `active` query param is retained
    for backward-compat but no longer drives rendering.
    """
    from apps.investigation_core.services.investigation_service import (
        InvestigationService,
    )
    from apps.investigation_workspace.branch.assembler import BranchAssembler
    from apps.investigation_workspace.branch.corridors import (
        compute_active_corridor,
        group_branches_by_corridor,
        semantic_edge_label,
    )
    from apps.investigation_workspace.branch.model import NodeKind

    # Phase 29 — graceful render-failure visibility. If the assembler or
    # grouping throws, return a small diagnostic block instead of a bare 500
    # that leaves the workspace stuck at "Loading investigation flow…".
    try:
        async with get_db() as db:
            inv = await InvestigationService(db).get_by_id(investigation_id)
            if not inv:
                raise HTTPException(status_code=404, detail="Investigation not found")
            target = inv.targets[0] if inv.targets else ""
            view = await BranchAssembler(db).assemble(investigation_id, target)

        corridor_order, corridor_branches, cluster_labels = group_branches_by_corridor(view)
    except HTTPException:
        raise
    except Exception as exc:
        # Log and surface a degraded but useful UI.
        import traceback

        from sdk import Logger
        Logger.error(
            "branch_flow_partial.render_failed",
            extra={
                "investigation_id": investigation_id,
                "exc_type":         type(exc).__name__,
                "exc_msg":          str(exc),
                "traceback":        traceback.format_exc(),
            },
        )
        return _render_flow_diagnostic(
            request=request,
            investigation_id=investigation_id,
            exc_type=type(exc).__name__,
            exc_msg=str(exc),
            stage="assembler / grouping",
        )

    # Active cluster: query param wins; "" means "no expanded corridor" (toggle
    # the previously-active off); unset → compute via priority scoring.
    if active == "":
        # Distinguish "param absent" from "param explicitly empty" via the
        # raw query string — FastAPI defaults to "" either way, so use the
        # raw request to disambiguate.
        if "active" in request.query_params:
            active_cluster = None      # explicit collapse
        else:
            active_cluster = compute_active_corridor(
                view, corridor_order, corridor_branches,
            )
    else:
        active_cluster = active

    # Build edge_kind lookup for the active corridor — needed so the partial
    # can render inline causal transitions ("↓ probe path", etc.).
    edge_kind_by_child_id: dict[str, str] = {}
    if active_cluster and active_cluster in corridor_branches:
        for branch in corridor_branches[active_cluster]:
            for e in branch.edges:
                edge_kind_by_child_id[e.child_id] = e.edge_kind

    def child_edge_kind(child) -> str:
        return edge_kind_by_child_id.get(child.node_id, "")

    # Walk helper for Jinja namespace aggregation
    def branch_walk(node):
        yield node
        for c in node.children:
            yield from branch_walk(c)

    # Determine the "next" branch in the active corridor (highest priority
    # available/remediation_pending action). Identical heuristic to the
    # React Flow client-side picker.
    from apps.investigation_workspace.branch.model import BranchState
    priority = {
        BranchState.REGRESSION:           5,
        BranchState.REMEDIATION_PENDING:  4,
        BranchState.VERIFICATION_RUNNING: 3,
        BranchState.AVAILABLE:            2,
        BranchState.ACTIVE:               1,
    }
    next_branch = None
    next_score = -1
    if active_cluster and active_cluster in corridor_branches:
        for branch in corridor_branches[active_cluster]:
            for n in branch_walk(branch.root):
                if n.kind not in (NodeKind.ACTION, NodeKind.REMEDIATION):
                    continue
                s = priority.get(n.state, -1)
                if s > next_score:
                    next_score = s
                    next_branch = n

    try:
        response = templates.TemplateResponse(
            "partials/branch_flow.html",
            {
                "request":           request,
                "investigation":     inv,
                "investigation_id":  investigation_id,
                "view":              view,
                "corridor_order":    corridor_order,
                "corridor_branches": corridor_branches,
                "cluster_labels":    cluster_labels,
                "active_cluster":    active_cluster,
                "next_branch":       next_branch,
                "semantic":          semantic_edge_label,
                "child_edge_kind":   child_edge_kind,
                "branch_walk":       branch_walk,
                "storyline_recent":  (view.storyline or [])[-5:],
            },
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return response
    except Exception as exc:
        import traceback

        from sdk import Logger
        Logger.error(
            "branch_flow_partial.template_render_failed",
            extra={
                "investigation_id": investigation_id,
                "exc_type":         type(exc).__name__,
                "exc_msg":          str(exc),
                "traceback":        traceback.format_exc(),
            },
        )
        return _render_flow_diagnostic(
            request=request,
            investigation_id=investigation_id,
            exc_type=type(exc).__name__,
            exc_msg=str(exc),
            stage="template render",
        )


def _render_flow_diagnostic(
    *, request: Request, investigation_id: str,
    exc_type: str, exc_msg: str, stage: str,
) -> HTMLResponse:
    """Phase 29 — operator-readable degraded view when flow rendering fails.

    Returns 200 (so HTMX still swaps it in) with a clearly-marked diagnostic
    block. Avoids the bare 500 + permanent "Loading investigation flow…"
    state caused by an uncaught exception during render.
    """
    body = f"""
    <section style="padding:1rem; max-width:880px;">
      <div style="border-left:3px solid var(--critical);
                  background: rgba(226,86,86,.08);
                  padding:.75rem 1rem; border-radius:0 6px 6px 0;
                  color: var(--text-secondary); font-size:.85rem;">
        <div style="font-weight:600; color: var(--critical); margin-bottom:.4rem;">
          Investigation flow renderer failed
        </div>
        <div style="font-size:.78rem; margin-bottom:.3rem;">
          The structured flow could not be built for this investigation.
          The data is preserved — only the renderer is degraded.
        </div>
        <div style="font-family: var(--mono, monospace); font-size:.72rem;
                    color: var(--text-muted); margin-top:.5rem;">
          stage: <strong style="color:var(--text-secondary);">{stage}</strong><br>
          investigation_id: <code>{investigation_id}</code><br>
          {exc_type}: {exc_msg}
        </div>
        <div style="margin-top:.6rem; font-size:.75rem;">
          <a href="/api/v1/validation/investigations" style="color:var(--accent,#4aa3df);">
            ← Back to investigations
          </a>
          ·
          <a target="_blank" style="color:var(--accent,#4aa3df);"
             href="/api/v1/validation/workspace/investigations/{investigation_id}/branches/topology.json">
            Inspect raw topology JSON
          </a>
        </div>
      </div>
    </section>
    """
    response = HTMLResponse(content=body, status_code=200)
    response.headers["Cache-Control"] = "no-store"
    return response


# ── Phase 37 — React Flow topology JSON + context panel ─────────────────


@router.get("/investigations/{investigation_id}/branches/topology.json")
async def branch_topology_json(investigation_id: str):
    """React Flow nodes + edges for the execution-topology UI.

    Phase 40 — if the investigation has no discoveries yet (fresh workspace
    open), auto-kick the bootstrap runtime so the topology starts evolving
    immediately. The runner persists real findings as it goes; subsequent
    fetches show the genuine branches.
    """
    from apps.investigation_core.services.investigation_service import (
        InvestigationService,
    )
    from apps.investigation_workspace.branch.assembler import BranchAssembler
    from apps.investigation_workspace.branch.topology_v2 import serialize_topology

    async with get_db() as db:
        inv = await InvestigationService(db).get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        target = inv.targets[0] if inv.targets else ""
        view = await BranchAssembler(db).assemble(investigation_id, target)

    # Phase 40 — bootstrap auto-trigger. Considered "empty" when no branch
    # has any discoveries below its surface root.
    if _view_is_empty(view):
        await _ensure_bootstrap_running(investigation_id, target)
        # Re-assemble so persisted findings from any in-flight bootstrap
        # show up. Cheap on an empty investigation.
        async with get_db() as db:
            view = await BranchAssembler(db).assemble(investigation_id, target)

    return serialize_topology(view)


@router.get("/investigations/{investigation_id}/workspace-data.json")
async def workspace_data_json(investigation_id: str, include_dropped: bool = False):
    """V1.4a — stage-card data for the tabbed workspace UI.

    Post-processes the existing topology JSON into a flat, category-grouped
    structure that Jinja2 templates and the polling loop consume directly.
    The React Flow topology endpoint is unchanged; this endpoint is additive.
    """
    from apps.investigation_core.services.investigation_service import (
        InvestigationService,
    )
    from apps.investigation_workspace.bootstrap.runtime import (
        get_run as get_bootstrap_run,
    )
    from apps.investigation_workspace.branch.assembler import BranchAssembler
    from apps.investigation_workspace.branch.topology_v2 import serialize_topology

    async with get_db() as db:
        inv = await InvestigationService(db).get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        target = inv.targets[0] if inv.targets else ""
        view = await BranchAssembler(db).assemble(investigation_id, target)

    if _view_is_empty(view):
        await _ensure_bootstrap_running(investigation_id, target)
        async with get_db() as db:
            view = await BranchAssembler(db).assemble(investigation_id, target)

    topology = serialize_topology(view)
    boot_run = get_bootstrap_run(investigation_id)

    # Build finding_id → phase map and findings_by_id from raw_data._phase.
    phase_map: dict[str, str] = {}
    findings_by_id: dict[str, dict] = {}
    validation_counts: dict[str, int] = {}
    try:
        from apps.scanner_orchestration.storage.finding_repo import (
            NormalizedFindingRepository,
        )
        async with get_db() as _db:
            findings = await NormalizedFindingRepository(_db).list_for_investigation(
                investigation_id
            )
            for f in findings:
                raw = f.raw_data or {}
                if isinstance(raw, dict):
                    p = raw.get("_phase")
                    if p:
                        phase_map[f.finding_id] = p
                findings_by_id[f.finding_id] = {
                    "finding_id":   f.finding_id,
                    "finding_type": f.finding_type,
                    "title":        f.title,
                    "description":  f.description,
                    "severity":     f.severity,
                    "endpoint":     f.endpoint or "",
                    "raw_data":     raw if isinstance(raw, dict) else {},
                }
    except Exception:
        pass

    # Merge validation status fields from DB
    try:
        from apps.scanner_orchestration.storage.finding_repo import (
            NormalizedFindingRepository,
        )
        async with get_db() as _vdb:
            v_map = await NormalizedFindingRepository(_vdb).map_validation_status(investigation_id)
        for fid, vdata in v_map.items():
            if fid in findings_by_id:
                findings_by_id[fid].update(vdata)
    except Exception:
        pass

    # Default all findings without validation fields to pending
    for fdata in findings_by_id.values():
        fdata.setdefault("validation_status", "pending")
        fdata.setdefault("validation_reason", None)
        fdata.setdefault("enumeration_gaps", [])

    # Compute validation status counts before filtering
    validation_counts = {"validated": 0, "incomplete": 0, "dropped": 0, "pending": 0}
    for fdata in findings_by_id.values():
        s = fdata.get("validation_status", "pending")
        if s in validation_counts:
            validation_counts[s] += 1

    # Filter dropped findings from view unless include_dropped requested
    if not include_dropped:
        findings_by_id = {
            fid: fd for fid, fd in findings_by_id.items()
            if fd.get("validation_status") != "dropped"
        }

    # Fetch ai_probe branches — synthetic findings not in topology; synthesized
    # into the exploit_tree directly in _build_exploit_tree.
    # Two cases:
    #   post-fix: branch.finding_id starts with "fnd_ai_" (correct)
    #   pre-fix:  branch.finding_id == investigation_id (Bug 1, fixed going forward)
    #             — cross-reference against ai_probe findings in findings_by_id
    ai_branches: list[dict] = []
    try:
        from apps.conductor.exploitation.branch_store import BranchReader as _BR
        _ai_records = await _BR().list_for_investigation(investigation_id)
        _ai_fids = {
            fid for fid, fd in (findings_by_id or {}).items()
            if fd.get("finding_type") == "ai_probe"
        }
        _paired_engines: set[str] = set()
        for r in _ai_records:
            if r.finding_id and r.finding_id.startswith("fnd_ai_"):
                # Post-fix: branch already references the correct ai_probe finding
                ai_branches.append({
                    "branch_id":  r.branch_id,
                    "finding_id": r.finding_id,
                    "engine_id":  r.engine_id,
                    "state":      r.state,
                })
                _paired_engines.add(r.engine_id)
            elif r.finding_id == investigation_id and _ai_fids and r.engine_id not in _paired_engines:
                # Pre-fix fallback: branch has investigation_id as finding_id;
                # pair it with the first unpaired ai_probe finding.
                _remaining = _ai_fids - {b["finding_id"] for b in ai_branches}
                if _remaining:
                    ai_branches.append({
                        "branch_id":  r.branch_id,
                        "finding_id": next(iter(_remaining)),
                        "engine_id":  r.engine_id,
                        "state":      r.state,
                    })
                    _paired_engines.add(r.engine_id)
    except Exception:
        pass

    # Fetch planner-dispatched branches for concept-linked engines that are NOT in
    # the SUGGESTIONS catalog (e.g. login_protection_probe, default_creds when run via
    # the planner loop).  These branches have real finding_ids and real concept_ids, but
    # no ghost action in the topology — so they're invisible on the mindmap without
    # this synthesis step.  Filter includes any engine with a CONCEPT_ENGINE_MAP entry;
    # this covers detection-class and any future planner-only concepts automatically.
    planner_branches: list[dict] = []
    try:
        from apps.conductor.constants import CONCEPT_ENGINE_MAP as _CEM_PB
        from apps.conductor.exploitation.branch_store import BranchReader as _PBR
        _concept_engines = {v for v in _CEM_PB.values() if v}
        _pb_records = await _PBR().list_for_investigation(investigation_id)
        for _pb_r in _pb_records:
            if (
                _pb_r.engine_id in _concept_engines
                and _pb_r.finding_id
                and not _pb_r.finding_id.startswith("fnd_ai_")
                and _pb_r.finding_id != investigation_id
            ):
                planner_branches.append({
                    "branch_id":  _pb_r.branch_id,
                    "finding_id": _pb_r.finding_id,
                    "engine_id":  _pb_r.engine_id,
                    "state":      _pb_r.state,
                })
    except Exception:
        pass

    return _build_workspace_data(
        topology, boot_run, investigation_id, target, phase_map, findings_by_id,
        validation_counts=validation_counts,
        ai_branches=ai_branches or None,
        planner_branches=planner_branches or None,
    )


@router.get("/investigations/{investigation_id}/exploitation-data.json")
async def exploitation_data_json(investigation_id: str):
    """V2.3 — branch state polling endpoint for the three-level mindmap.

    Returns all exploitation_branches rows for this investigation keyed by
    branch_id. Returns 200 with empty branches dict when no engines have run
    yet. BranchReader's first production consumer.

    JSON shape (snake_case — matches workspace-data.json convention):
        {
            "investigation_id": "<id>",
            "branches": {
                "<branch_id>": {
                    "branch_id", "finding_id", "engine_id", "technique_class",
                    "state", "operator_params", "artifact", "exhaustion_record",
                    "stage_log", "created_at", "updated_at"
                },
                ...
            }
        }
    """
    from apps.conductor.exploitation.branch_store import BranchReader

    reader = BranchReader()
    records = await reader.list_for_investigation(investigation_id)
    branches = {
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
        for r in records
    }

    # Phase A: include agent_state so Zone A can render STATE read-only from the poll.
    # get_or_init ensures STATE is built on first load (seeds pending from enum findings).
    agent_state: dict = {}
    try:
        from apps.conductor.agent_state import get_or_init_agent_state_async
        agent_state = await get_or_init_agent_state_async(investigation_id)
    except Exception:
        pass  # Zone A degrades to Idle if agent_state unavailable

    # Phase D: include pending unknown count for Zone B badge.
    unknown_count: int = 0
    try:
        from apps.conductor.unknown_store import count_pending_async
        unknown_count = await count_pending_async()  # cross-investigation count
    except Exception:
        pass

    return {
        "investigation_id": investigation_id,
        "branches":         branches,
        "agent_state":      agent_state,
        "unknown_count":    unknown_count,
    }


@router.get("/investigations/{investigation_id}/branch/{branch_id}/log")
async def branch_progress_log(
    investigation_id: str,
    branch_id: str,
    tail: int = 50,
):
    """Branch-scoped progress log — returns the last `tail` stage_log entries for one branch.

    Each entry: {state, at, phase?, attempted?, total?, event?, candidate?, ...}
    Used by the mindmap right-side panel to tail live progress while a branch is running.
    Empty list when branch has no events yet. Bounded by the `tail` param (default 50).
    """
    from apps.conductor.exploitation.branch_store import BranchReader

    reader = BranchReader()
    record = await reader.get(branch_id)
    if record is None or record.investigation_id != investigation_id:
        raise HTTPException(status_code=404, detail="Branch not found")

    log: list[dict] = record.stage_log or []
    # Return last `tail` entries (chronological — oldest first, newest last)
    tail = max(1, min(tail, 200))
    entries = log[-tail:] if len(log) > tail else list(log)

    return {
        "branch_id":    branch_id,
        "state":        record.state,
        "engine_id":    record.engine_id,
        "events":       entries,
        "total_events": len(log),
    }


# ── V2.5 Step 4 — ACTION block parsing ───────────────────────────────────────

_APPROVED_ENGINES = frozenset({
    "credential_brute", "sqli_auth_bypass", "access_control", "default_creds",
    "xss_reflected", "cmdi_reflected", "cmdi_blind_time", "cmdi_blind_boolean",
    "metasploit_recipe", "username_enum", "js_spider",
})


def _parse_qwen_action(response_text: str, approved_engines: frozenset) -> tuple[str, dict | None]:
    """Parse an optional ACTION block from the end of a Qwen response.

    Returns (clean_text, action_dict_or_None).

    The ACTION block format is:
        ACTION:{"engine_id":"...", "finding_type":"...", "reason":"..."}

    Parsing never raises. Malformed JSON or unknown engine_id → action=None.
    """
    text = response_text
    action = None

    marker = "\nACTION:"
    idx = response_text.find(marker)
    if idx == -1:
        marker = "ACTION:"
        idx = response_text.find(marker)

    if idx != -1:
        text = response_text[:idx].strip()
        action_str = response_text[idx + len(marker):].strip().split("\n")[0].strip()

        # Case 1: null / None → no action
        if action_str.lower() in ("null", "none", ""):
            pass  # action stays None

        # Case 2: plain engine name with no JSON (e.g. "ACTION: access_control")
        elif action_str in approved_engines:
            action = {
                "engine_id": action_str,
                "finding_type": None,
                "reason": "AI recommendation",
                "extended_payloads": [],
            }

        # Case 4: colon-separated format (e.g. "ACTION:access_control:reason text")
        # Extract engine_id as the segment between first and second colon.
        elif ":" in action_str and action_str.split(":")[0].strip() in approved_engines:
            action = {
                "engine_id": action_str.split(":")[0].strip(),
                "finding_type": None,
                "reason": "AI recommendation",
                "extended_payloads": [],
            }

        # Case 3: JSON object (possibly with leading space already stripped above)
        else:
            try:
                parsed = json.loads(action_str)
                if parsed.get("engine_id") in approved_engines:
                    action = {
                        "engine_id":    parsed["engine_id"],
                        "finding_type": parsed.get("finding_type", ""),
                        "reason":       str(parsed.get("reason", ""))[:200],
                    }
                    # Extract and validate extended_payloads if present
                    raw_payloads = parsed.get("extended_payloads", [])
                    if isinstance(raw_payloads, list):
                        valid_payloads = []
                        for p in raw_payloads:
                            if (isinstance(p, dict) and
                                    isinstance(p.get("endpoint"), str) and
                                    isinstance(p.get("body"), dict)):
                                valid_payloads.append({
                                    "endpoint": p["endpoint"],
                                    "method": str(p.get("method", "POST")).upper(),
                                    "body": p["body"],
                                })
                        if valid_payloads:
                            action["extended_payloads"] = valid_payloads
            except Exception:
                pass  # malformed → null

    return text, action


@router.post("/investigations/{investigation_id}/qwen/chat/stream")
async def qwen_chat_stream(investigation_id: str, request: Request):
    """V2.9B — Streaming SSE variant of qwen_chat.

    Same request body: {"message": str, "history": list[dict]}

    Returns text/event-stream. Events:
        data: {"type": "token", "content": "..."}
        data: {"type": "action", "action": {...}}
        data: {"type": "done"}

    On Ollama failure, emits a single error token then done.
    Existing POST /qwen/chat endpoint is unchanged.
    """
    from fastapi.responses import StreamingResponse as _SR
    import logging as _logging
    _logger = _logging.getLogger("investigation_workspace.api.routes.qwen_chat_stream")

    try:
        body = await request.json()
    except Exception:
        body = {}

    message: str = body.get("message", "")
    history: list = body.get("history", [])
    if not isinstance(history, list):
        history = []

    from apps.conductor.qwen.action_schema import (
        _exploitation_engine_ids as _stream_eids,
        build_action_schema as _stream_schema,
    )
    from apps.conductor.qwen.technique_router import (
        resolve_technique as _resolve_tech,
        ENGINE_LABELS as _stream_labels,
        ENGINE_DESCRIPTIONS as _stream_descs,
        build_engine_menu as _stream_menu,
    )
    _stream_engine_ids = _stream_eids()
    op_params: dict = dict(body.get("operator_params") or {})
    _provided_self = op_params.get("provided_self_user") or ""

    # ── Persist objective, target_user, provided_self_user (BEFORE planner call) ─
    if message and len(message.strip()) > 20:
        _msg_strip = message.strip()
        try:
            from apps.conductor.investigation_state import (
                load_state_async as _cs_load, save_state_async as _cs_save,
            )
            _cs_state = await _cs_load(investigation_id)
            if not _cs_state.objective:
                _cs_state.objective = _msg_strip
                await _cs_save(_cs_state)
        except Exception:
            pass
        try:
            from apps.conductor.template_executor import extract_target_account as _eta_cs
            from apps.conductor.agent_state import (
                load_agent_state_async as _lasa_cs,
                save_agent_state_async as _sasa_cs,
                _get_state_lock as _gsl_cs,
            )
            _cs_acct = _eta_cs(_msg_strip)
            if _cs_acct or _provided_self:
                async with _gsl_cs(investigation_id):
                    _cs_as = await _lasa_cs(investigation_id)
                    if _cs_as and "goal" in _cs_as:
                        if _cs_acct and not _cs_as["goal"].get("target_user"):
                            _cs_as["goal"]["target_user"] = _cs_acct
                        if _provided_self and not _cs_as["goal"].get("provided_self_user"):
                            _cs_as["goal"]["provided_self_user"] = _provided_self
                        await _sasa_cs(investigation_id, _cs_as)
        except Exception:
            pass

    # ── plan_next_step — ONE selection authority on the chat path ─────────────
    _planner_action: "dict | None" = None
    try:
        from apps.conductor.planner import plan_next_step as _cs_plan
        from apps.conductor.agent_state import load_agent_state_async as _cs_las
        _cs_agent = await _cs_las(investigation_id)
        if _cs_agent and "goal" in _cs_agent:
            _cs_dec = _cs_plan(_cs_agent)
            if _cs_dec.action == "execute" and _cs_dec.engine_id:
                _planner_action = {
                    "engine_id":    _cs_dec.engine_id,
                    "concept_id":   _cs_dec.concept_id,
                    "finding_type": "",
                    "reason":       _cs_dec.log_entry,
                    "source":       "planner",
                }
    except Exception as _cs_pe:
        _logger.debug("chat: plan_next_step failed: %s", _cs_pe)

    # ── Intent detection — NOT dispatch ───────────────────────────────────────
    # resolve_technique detects named technique intent (for conversational reply).
    # Engine selection comes from plan_next_step — not from this match.
    _stream_route = _resolve_tech(message)
    if _stream_route.is_explicit:
        # Branch 1: operator named a technique — use intent for reply; planner dispatches.
        if _planner_action:
            _det_text = (
                f"Got it. The planner starts with: "
                f"{_planner_action['reason'][:100]}. Approve to begin."
            )
        elif _stream_route.engine_id is not None:
            _det_text = (
                f"'{_stream_route.technique_phrase}' noted. "
                "Initialize agent state via /planner/run first to enable planner sequencing."
            )
        else:
            _det_text = (
                f"'{_stream_route.technique_phrase.title()}' has no engine yet. "
                "Available: " + _stream_menu(_stream_engine_ids) + "."
            )

        async def _det_generator():
            import json as _json
            yield f"data: {_json.dumps({'type': 'token', 'content': _det_text})}\n\n"
            if _planner_action:
                yield f"data: {_json.dumps({'type': 'action', 'action': _planner_action})}\n\n"
            yield f"data: {_json.dumps({'type': 'done'})}\n\n"

        return _SR(
            _det_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ── Branch 2: open ask — Qwen for conversation only; planner for selection ─
    try:
        from apps.conductor.qwen.context_builder import build_investigation_context
        context_str = await build_investigation_context(investigation_id, operator_message=message)
    except Exception:
        context_str = "Investigation context unavailable."

    # Conversational-only prompt — no engine_id selection. plan_next_step is the selector.
    _SYSTEM_PROMPT_CONV = (
        "You are a security testing assistant. "
        "Acknowledge the operator's request in 1-2 concise sentences. "
        "The system's planner automatically selects and sequences the technique. "
        "Do NOT recommend or name specific engines — just acknowledge conversationally."
    )
    system_content = _SYSTEM_PROMPT_CONV + "\n\n" + context_str
    messages: list[dict] = [{"role": "system", "content": system_content}]
    for h in history:
        if isinstance(h, dict) and "role" in h and "content" in h:
            messages.append({"role": h["role"], "content": h["content"]})
    if message:
        messages.append({"role": "user", "content": message})

    _chat_planner_action = _planner_action   # closure capture for the generator

    async def _event_generator():
        import json as _json
        import httpx as _httpx
        from apps.conductor.qwen import client as _qc

        try:
            payload = {
                "model": _qc.MODEL,
                "messages": messages,
                "stream": True,
                # No format binding — conversational text only, not structured engine JSON.
                "options": {"temperature": 0.3, "num_ctx": 4096, "num_predict": 150},
            }
            async with _httpx.AsyncClient(timeout=90) as hx:
                async with hx.stream(
                    "POST", f"{_qc.OLLAMA_BASE_URL}/api/chat", json=payload
                ) as resp:
                    if resp.status_code >= 400:
                        raise RuntimeError(f"Ollama HTTP {resp.status_code}")
                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = _json.loads(line)
                            token = chunk.get("message", {}).get("content", "")
                            if token:
                                yield f"data: {_json.dumps({'type': 'token', 'content': token})}\n\n"
                        except Exception:
                            continue
        except Exception as exc:
            _logger.warning("qwen_chat_stream: Qwen call failed: %s", exc)
            yield f"data: {_json.dumps({'type': 'token', 'content': 'AI unavailable.'})}\n\n"

        # Planner action — sole selection authority (emitted regardless of Qwen success)
        if _chat_planner_action:
            yield f"data: {_json.dumps({'type': 'action', 'action': _chat_planner_action})}\n\n"
        else:
            _menu = _stream_menu(sorted(_stream_engine_ids))
            yield (
                f"data: {_json.dumps({'type': 'token', 'content': chr(10) + 'No planner state — initialize via /planner/run first. I can run: ' + _menu + '.'})}\n\n"
            )
        yield f"data: {_json.dumps({'type': 'done'})}\n\n"

    return _SR(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/investigations/{investigation_id}/qwen/chat")
async def qwen_chat(investigation_id: str, request: Request):
    """V2.5 Step 3 — persistent Qwen chat panel backend.

    Request body: {"message": str, "history": list[dict]}

    Builds investigation context from DB, prepends it as a system message,
    and calls the Qwen client. Always returns HTTP 200 — Qwen failures surface
    as an advisory message in the response body, never as a 5xx.

    Response: {"response": str, "investigation_id": str}
    """
    import logging
    _logger = logging.getLogger("investigation_workspace.api.routes.qwen_chat")

    _UNAVAILABLE = (
        "AI assistant is currently unavailable. Check /admin/ai/ping."
    )
    from apps.conductor.qwen.action_schema import (
        _exploitation_engine_ids as _chat_eids,
        build_action_schema as _chat_schema,
    )
    from apps.conductor.qwen.technique_router import (
        resolve_technique as _chat_resolve,
        ENGINE_LABELS as _chat_labels,
        ENGINE_DESCRIPTIONS as _chat_descs,
        build_engine_menu as _chat_menu,
    )
    _chat_engine_ids = _chat_eids()

    try:
        body = await request.json()
    except Exception:
        body = {}

    message: str = body.get("message", "")
    history: list = body.get("history", [])
    if not isinstance(history, list):
        history = []
    qc_op_params: dict = dict(body.get("operator_params") or {})
    _qc_provided_self = qc_op_params.get("provided_self_user") or ""

    # ── Persist objective, target_user, provided_self_user (BEFORE planner call) ─
    if message and len(message.strip()) > 20:
        _qc_msg = message.strip()
        try:
            from apps.conductor.investigation_state import load_state_async, save_state_async
            _qc_inv_state = await load_state_async(investigation_id)
            if not _qc_inv_state.objective:
                _qc_inv_state.objective = _qc_msg
                await save_state_async(_qc_inv_state)
                _logger.debug("qwen_chat: objective persisted (%d chars)", len(_qc_msg))
        except Exception as _obj_exc:
            _logger.debug("qwen_chat: objective persist failed: %s", _obj_exc)
        try:
            from apps.conductor.template_executor import extract_target_account as _eta_qc
            from apps.conductor.agent_state import (
                load_agent_state_async as _lasa_qc,
                save_agent_state_async as _sasa_qc,
                _get_state_lock as _gsl_qc,
            )
            _qc_acct = _eta_qc(_qc_msg)
            if _qc_acct or _qc_provided_self:
                async with _gsl_qc(investigation_id):
                    _qc_as = await _lasa_qc(investigation_id)
                    if _qc_as and "goal" in _qc_as:
                        if _qc_acct and not _qc_as["goal"].get("target_user"):
                            _qc_as["goal"]["target_user"] = _qc_acct
                        if _qc_provided_self and not _qc_as["goal"].get("provided_self_user"):
                            _qc_as["goal"]["provided_self_user"] = _qc_provided_self
                        await _sasa_qc(investigation_id, _qc_as)
                        _logger.debug("qwen_chat: target_user=%r provided_self=%r",
                                      _qc_acct, _qc_provided_self)
        except Exception as _d_exc:
            _logger.debug("qwen_chat: goal persist failed: %s", _d_exc)

    # ── plan_next_step — ONE selection authority on the chat path ─────────────
    _qc_planner_action: "dict | None" = None
    try:
        from apps.conductor.planner import plan_next_step as _qc_plan
        from apps.conductor.agent_state import load_agent_state_async as _qc_las
        _qc_agent = await _qc_las(investigation_id)
        if _qc_agent and "goal" in _qc_agent:
            _qc_dec = _qc_plan(_qc_agent)
            if _qc_dec.action == "execute" and _qc_dec.engine_id:
                _qc_planner_action = {
                    "engine_id":    _qc_dec.engine_id,
                    "concept_id":   _qc_dec.concept_id,
                    "finding_type": "",
                    "reason":       _qc_dec.log_entry,
                    "source":       "planner",
                }
    except Exception as _qc_pe:
        _logger.debug("qwen_chat: plan_next_step failed: %s", _qc_pe)

    # ── Intent detection — NOT dispatch ───────────────────────────────────────
    _chat_route = _chat_resolve(message)
    if _chat_route.is_explicit:
        # Branch 1: operator named a technique — planner dispatches, not the name.
        if _qc_planner_action:
            _c_text = (
                f"Got it. The planner starts with: "
                f"{_qc_planner_action['reason'][:100]}. Approve to begin."
            )
        elif _chat_route.engine_id is not None:
            _c_text = (
                f"'{_chat_route.technique_phrase}' noted. "
                "Initialize agent state via /planner/run first to enable planner sequencing."
            )
        else:
            _c_text = (
                f"'{_chat_route.technique_phrase.title()}' has no engine yet. "
                "Available: " + _chat_menu(_chat_engine_ids) + "."
            )
        return {
            "response": _c_text,
            "investigation_id": investigation_id,
            "action": _qc_planner_action,
        }

    # ── Branch 2: open ask — Qwen for conversation only; planner for selection ─
    # Conversational-only prompt — no engine_id selection. plan_next_step is the selector.
    _SYSTEM_PROMPT = (
        "You are a security testing assistant. "
        "Acknowledge the operator's request in 1-2 concise sentences. "
        "The system's planner automatically selects and sequences the technique. "
        "Do NOT recommend or name specific engines — just acknowledge conversationally."
    )

    try:
        from apps.conductor.qwen.context_builder import build_investigation_context
        context_str = await build_investigation_context(investigation_id, operator_message=message)
    except Exception:
        context_str = "Investigation context unavailable."

    system_content = _SYSTEM_PROMPT + "\n\n" + context_str
    messages: list[dict] = [{"role": "system", "content": system_content}]
    for h in history:
        if isinstance(h, dict) and "role" in h and "content" in h:
            messages.append({"role": h["role"], "content": h["content"]})
    if message:
        messages.append({"role": "user", "content": message})

    try:
        from apps.conductor.qwen import client as _qwen_client
        import httpx as _httpx
        payload: dict = {
            "model": _qwen_client.MODEL,
            "messages": messages,
            "stream": False,
            # No format binding — conversational text output only, not structured engine JSON.
            "options": {"temperature": 0.3, "num_ctx": 4096, "num_predict": 150},
        }
        async with _httpx.AsyncClient(timeout=90) as _hx:
            _resp = await _hx.post(
                f"{_qwen_client.OLLAMA_BASE_URL}/api/chat", json=payload
            )
        if _resp.status_code >= 400:
            raise RuntimeError(f"Ollama HTTP {_resp.status_code}")
        _data = _resp.json()
        clean_text: str = (
            _data.get("message", {}).get("content", "")
            or _data.get("response", "")
            or _UNAVAILABLE
        )
    except Exception as exc:
        _logger.warning("qwen_chat: Qwen call failed: %s", exc)
        clean_text = _UNAVAILABLE

    # Planner action — sole selection authority; no parse_structured_output needed.
    if _qc_planner_action is None:
        _null_menu = _chat_menu(sorted(_chat_engine_ids))
        clean_text = (clean_text or "") + (
            "\n\nNo planner state — initialize via /planner/run. I can run: " + _null_menu + "."
        )

    return {
        "response": clean_text or "",
        "investigation_id": investigation_id,
        "action": _qc_planner_action,
    }


def _current_phase(boot_run) -> str:
    """Return current execution phase for this investigation."""
    if boot_run is None:
        return "complete"
    if boot_run.recon_run and boot_run.recon_run.completed_at is None:
        return "recon"
    if boot_run.enumeration_run and boot_run.enumeration_run.completed_at is None:
        return "enumeration"
    if boot_run.exploitation_run and boot_run.exploitation_run.completed_at is None:
        return "exploitation"
    return "complete"


def _build_workspace_data(
    topology: dict,
    boot_run,
    investigation_id: str,
    target: str,
    phase_map: dict[str, str] | None = None,
    findings_by_id: dict[str, dict] | None = None,
    validation_counts: dict[str, int] | None = None,
    ai_branches: list | None = None,
    planner_branches: list | None = None,
) -> dict:
    """Transform React Flow topology JSON into stage-card format.

    V1.4a — consumes the existing serialize_topology() output and returns
    a structure suitable for Jinja2 template rendering and JS polling.
    """
    nodes = topology.get("nodes", [])
    edges = topology.get("edges", [])
    meta  = topology.get("meta", {})

    # Build lookup structures from the flat node + edge lists
    nodes_by_id: dict[str, dict] = {n["id"]: n for n in nodes}
    children_map: dict[str, list[str]] = {}
    for edge in edges:
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        if src and tgt:
            children_map.setdefault(src, []).append(tgt)

    def _collect_with_parent(start_id: str) -> list[dict]:
        """Iterative DFS — cards with _tree_id and parent_tid set.

        Each card records:
          _tree_id   — the topology node's own id (stable key for tree building)
          parent_tid — the topology id of the nearest rendered ancestor
                       (None for finding-type roots)

        Transparent topology nodes (category, exploitation_path, non-ghost
        action) pass through: their children inherit the transparent node's
        rendered-parent unchanged.

        Execution stages chain through prev_id exactly as _overlay_execution_runs
        does (finding → s0 → s1 → r0), so the recursive tree mirrors the
        real topology depth.
        """
        result: list[dict] = []
        # Stack items: (node_id, last_rendered_ancestor_topology_id)
        stack: list[tuple[str, str | None]] = [(start_id, None)]
        seen: set[str] = set()
        while stack:
            node_id, rendered_parent_tid = stack.pop()
            if node_id in seen:
                continue
            seen.add(node_id)
            node = nodes_by_id.get(node_id)
            if not node:
                continue
            ntype = node.get("type", "")
            card  = _node_to_stage_card(node)
            if card is not None:
                card["_tree_id"]   = node["id"]
                card["parent_tid"] = None if ntype == "finding" else rendered_parent_tid
                result.append(card)
                next_rendered_parent = node["id"]
            else:
                # Transparent — children inherit the current rendered parent
                next_rendered_parent = rendered_parent_tid
            for child_id in reversed(children_map.get(node_id, [])):
                if child_id not in seen:
                    stack.append((child_id, next_rendered_parent))
        return result

    def _build_stage_tree(flat_cards: list[dict]) -> list[dict]:
        """Build a recursive {card, children} tree from DFS-ordered flat list.

        DFS pre-order guarantees every parent appears before its children,
        so a single pass suffices. _tree_id and parent_tid are stripped from
        the emitted card dicts (internal bookkeeping only).
        """
        tree_nodes: dict[str, dict] = {}   # _tree_id → tree node
        roots: list[dict] = []

        for card in flat_cards:
            tree_id    = card.pop("_tree_id")
            parent_tid = card.pop("parent_tid")
            tn = {"card": card, "children": []}
            tree_nodes[tree_id] = tn
            if parent_tid is None:
                roots.append(tn)
            elif parent_tid in tree_nodes:
                tree_nodes[parent_tid]["children"].append(tn)
            else:
                roots.append(tn)   # orphan — promote to root
        return roots

    def _node_to_stage_card(node: dict) -> dict | None:
        ntype = node.get("type", "")
        data  = node.get("data", {})
        title = data.get("title") or data.get("label") or ""
        sub   = data.get("subtitle") or ""

        # Ghost action nodes (type="action" with ghost_state="ghost") are
        # suggested-next probe actions. R2 restore: map them to "ready" cards.
        if ntype in ("finding", "action"):
            ghost = data.get("ghost_state")
            if ghost == "ghost":
                # Use disc-{finding_id} as the node_id so the context panel
                # route handles it correctly (shows suggestions + Execute buttons).
                finding_id = data.get("finding_id", "")
                disc_nid   = f"disc-{finding_id}" if finding_id else node["id"]
                return {
                    "type":      "ready",
                    "label":     title,
                    "sub_label": "ready · not executed",
                    "status":    "ready",
                    "bundle_id": None,
                    "node_id":   disc_nid,
                    "action_kind": data.get("action_kind", ""),
                    "finding_id":  finding_id,
                }
            if ntype == "action":
                return None  # non-ghost action nodes are not shown as stage cards
            return {
                "type":      "stage",
                "label":     title,
                "sub_label": sub,
                "status":    "completed",
                "bundle_id": None,
                "node_id":   node["id"],
            }

        if ntype == "execution_stage":
            status = data.get("status", "completed")
            return {
                "type":      "stage",
                "label":     title,
                "sub_label": sub,
                "status":    status,
                "bundle_id": None,
                "node_id":   node["id"],
            }

        if ntype == "outcome":
            kind = data.get("kind", "")
            if kind in ("blocked", "note"):
                return {
                    "type":      "warning",
                    "label":     title,
                    "sub_label": sub,
                    "status":    "warning",
                    "bundle_id": None,
                    "node_id":   node["id"],
                }
            return {
                "type":      "stage",
                "label":     title,
                "sub_label": sub,
                "status":    "completed",
                "bundle_id": None,
                "node_id":   node["id"],
            }

        if ntype == "capture":
            bundle_id    = data.get("bundle_id", "")
            bundle_label = data.get("label", "Capture")
            artifact_count = data.get("artifact_count", 0)
            sub_label = (
                f"{artifact_count} artifact{'s' if artifact_count != 1 else ''}"
                " · click to view bundle"
                if artifact_count
                else "click to view bundle"
            )
            return {
                "type":      "capture",
                "label":     f"Capture: {bundle_label}",
                "sub_label": sub_label,
                "status":    "capture",
                "bundle_id": bundle_id,
                "node_id":   node["id"],
            }

        return None  # surface, category, exploitation_path — skip

    categories: list[dict] = []

    # ── Category panes ────────────────────────────────────────────────────
    cat_nodes = [n for n in nodes if n.get("type") == "category"]
    for cat_node in cat_nodes:
        cat_data  = cat_node.get("data", {})
        cat_slug  = cat_data.get("category_id") or cat_node["id"].replace("cat-", "")
        # Category nodes use "title" for the label and "subtitle" for the description
        cat_label = cat_data.get("title") or cat_data.get("label", "Unknown")
        cat_desc  = cat_data.get("subtitle") or cat_data.get("description", "")

        flat_cards  = _collect_with_parent(cat_node["id"])
        stage_tree  = _build_stage_tree(flat_cards)
        capture_count = sum(1 for c in flat_cards if c["type"] == "capture")

        if capture_count:
            cap_word  = "capture" if capture_count == 1 else "captures"
            desc_full = f"{cat_desc} · {capture_count} {cap_word}"
        else:
            finding_count = len(stage_tree)  # roots == distinct findings
            desc_full = f"{cat_desc} · {finding_count} finding{'s' if finding_count != 1 else ''}"

        categories.append({
            "slug":          cat_slug,
            "label":         cat_label,
            "description":   desc_full,
            "stage_count":   len(flat_cards),
            "capture_count": capture_count,
            "is_done":       capture_count > 0,
            "stage_tree":    stage_tree,
        })

    # ── Default tab ────────────────────────────────────────────────────────
    default_tab = categories[0]["slug"] if categories else "recon"
    for cat in categories:
        if cat.get("capture_count", 0) > 0:
            default_tab = cat["slug"]
            break

    # ── Pending actions tray ───────────────────────────────────────────────
    # Collect next_actions with operator-required inputs from completed
    # execution outcomes.  Rendered as a dedicated ActionTray in the main
    # workspace area (not the side panel) so inputs aren't wiped by
    # panel refresh cycles while the operator is typing.
    pending_actions = _collect_pending_actions(investigation_id)

    # ── Phase buckets ─────────────────────────────────────────────────────
    # Bucket finding_ids by phase using _phase stored in raw_data.
    # Falls back to "recon" for findings written before V1 PR1.
    _phase_map = phase_map or {}
    _fbi = findings_by_id or {}
    phases: dict[str, dict] = {
        "recon":        {"finding_ids": []},
        "enumeration":  {"finding_ids": []},
        "exploitation": {"finding_ids": []},
    }
    for node in nodes:
        if node.get("type") == "finding":
            fid = node.get("data", {}).get("finding_id", "")
            if not fid:
                # node id is disc-{finding_id}
                nid = node.get("id", "")
                fid = nid[len("disc-"):] if nid.startswith("disc-") else nid
            if fid:
                phase_key = _phase_map.get(fid, "recon")
                if phase_key not in phases:
                    phase_key = "recon"
                phases[phase_key]["finding_ids"].append(fid)

    # ── Phase aggregations ────────────────────────────────────────────────
    for phase_key in phases:
        phases[phase_key]["aggregations"] = _build_aggregations(
            phase_key, phases[phase_key]["finding_ids"], _fbi
        )

    # ── Exploit tree ──────────────────────────────────────────────────────
    exploit_tree = _build_exploit_tree(
        nodes, edges, investigation_id,
        phase_map=_phase_map,
        ai_branches=ai_branches,
        findings_by_id=_fbi,
        planner_branches=planner_branches,
    )

    # ── Layer 2 technique options — deterministic, no ChromaDB ────────────
    # Scoped to each finding's justified technique families via vault_selector
    # relationship layer. Consumed by the mindmap for operator selection UI.
    try:
        from apps.conductor.vault_selector import sync_scoped_options as _sync_scoped
        _technique_opts: dict = {}
        for fid, fd in _fbi.items():
            ftype = fd.get("finding_type", "")
            if ftype:
                opts = _sync_scoped(ftype)
                _technique_opts[fid] = [
                    {
                        "engine_id":  o.engine_id,
                        "concept_id": o.concept_id,
                        "title":      o.title,
                        "source":     o.source,
                    }
                    for o in opts if o.engine_id  # skip advisory-only concepts
                ]
    except Exception:
        _technique_opts = {}

    return {
        "investigation_id":    investigation_id,
        "target":              target,
        "is_recon_running":       (
            boot_run is not None
            and boot_run.recon_run is not None
            and boot_run.recon_run.completed_at is None
        ),
        "is_enumeration_running": (
            boot_run is not None
            and boot_run.enumeration_run is not None
            and boot_run.enumeration_run.completed_at is None
        ),
        "is_exploitation_running": (
            boot_run is not None
            and boot_run.exploitation_run is not None
            and boot_run.exploitation_run.completed_at is None
        ),
        "current_phase":          _current_phase(boot_run),
        "has_active_execution":   meta.get("has_active_execution", False),
        "categories":          categories,
        "default_tab":         default_tab,
        "meta":                meta,
        "pending_actions":     pending_actions,
        "phases":              phases,
        "exploit_tree":        exploit_tree,
        "validation_counts":   validation_counts or {},
        "technique_options_by_finding": _technique_opts,
    }


def _collect_ghost_actions(
    start_id: str,
    children_map: dict[str, list[str]],
    nodes_by_id: dict[str, dict],
) -> list[dict]:
    """BFS from start_id; return all descendant action nodes with ghost_state=ghost."""
    result: list[dict] = []
    visited: set[str] = set()
    stack = list(children_map.get(start_id, []))
    while stack:
        nid = stack.pop()
        if nid in visited:
            continue
        visited.add(nid)
        n = nodes_by_id.get(nid)
        if not n:
            continue
        if n.get("type") == "action" and n.get("data", {}).get("ghost_state") == "ghost":
            result.append(n)
        else:
            stack.extend(children_map.get(nid, []))
    return result


def _build_exploit_tree(
    nodes: list[dict],
    edges: list[dict],
    investigation_id: str,
    phase_map: dict[str, str] | None = None,
    ai_branches: list | None = None,
    findings_by_id: dict[str, dict] | None = None,
    planner_branches: list | None = None,
) -> dict:
    """Build React Flow node+edge data for the Exploitation mind tree.

    Walks topology nodes to find finding nodes with ghost action children,
    and emits a flat RF node list with arm/execute metadata attached.
    """
    from apps.investigation_workspace.categories.catalog import (
        for_finding_type as _cat_for_type,
    )
    from apps.conductor.constants import CONCEPT_ENGINE_MAP as _CEM
    _engine_to_concept: dict[str, str] = {v: k for k, v in _CEM.items() if v}
    nodes_by_id: dict[str, dict] = {n["id"]: n for n in nodes}
    children_map: dict[str, list[str]] = {}
    for e in edges:
        src = e.get("source", "")
        tgt = e.get("target", "")
        if src and tgt:
            children_map.setdefault(src, []).append(tgt)

    tree_nodes: list[dict] = []
    tree_edges: list[dict] = []
    seen_findings: set[str] = set()

    for node in nodes:
        if node.get("type") != "finding":
            continue
        d = node.get("data", {})
        fid = d.get("finding_id", "")
        if not fid:
            nid = node.get("id", "")
            fid = nid[len("disc-"):] if nid.startswith("disc-") else nid
        if not fid or fid in seen_findings:
            continue
        seen_findings.add(fid)

        # Skip Recon-phase findings — their suggestions are not exploitation actions.
        if phase_map and phase_map.get(fid) == "recon":
            continue

        ghost_actions = _collect_ghost_actions(node["id"], children_map, nodes_by_id)
        if not ghost_actions:
            continue

        # Finding node
        tree_nodes.append({
            "id": f"finding-{fid}",
            "data": {
                "kind":          "finding",
                "label":         d.get("title", "Finding"),
                "sub_label":     d.get("finding_type", ""),
                "category_id":   _cat_for_type(d.get("finding_type", "")).category_id,
                "finding_id":    fid,
                "node_id":       node["id"],
                "execute_url":   None,
                "executed":      False,
                "guidance_only": False,
                "action_kind":   "",
            },
        })

        for action_node in ghost_actions:
            ad = action_node.get("data", {})
            action_kind = ad.get("action_kind", "")
            action_id = f"action-{action_kind}-{fid}"

            tree_nodes.append({
                "id": action_id,
                "data": {
                    "kind":          "action",
                    "label":         ad.get("title", action_kind),
                    "sub_label":     action_kind,
                    "action_kind":   action_kind,
                    "finding_id":    fid,
                    "node_id":       action_node["id"],
                    "execute_url": (
                        f"/api/v1/validation/workspace/investigations/{investigation_id}"
                        f"/finding/{fid}/suggest/{action_kind}/execute"
                    ),
                    "concept_id":    _engine_to_concept.get(action_kind, ""),
                    "executed":      ad.get("status") == "completed",
                    "guidance_only": ad.get("guidance_only", False),
                },
            })
            tree_edges.append({
                "id":     f"e-finding-{fid}-{action_id}",
                "source": f"finding-{fid}",
                "target": action_id,
            })

    # Synthesize finding + action nodes for ai_probe branches.
    # ai_probe findings are written directly to normalized_findings (bypassing the
    # topology branch tree), so they never reach the topology serializer and would
    # otherwise be invisible to this function. Synthesize them from the branch
    # records themselves.
    if ai_branches:
        _fbi = findings_by_id or {}
        # Track which finding_ids are already rendered as finding nodes in tree_nodes.
        # seen_findings includes findings that were visited but SKIPPED (no ghost
        # actions), so we cannot use it as the "already rendered" guard here.
        _rendered_finding_ids = {
            n["data"].get("finding_id", "")
            for n in tree_nodes
            if n.get("data", {}).get("kind") == "finding"
        }
        for branch in ai_branches:
            fid = branch.get("finding_id", "")
            engine_id = branch.get("engine_id", "")
            if not fid or not engine_id or fid in _rendered_finding_ids:
                continue
            seen_findings.add(fid)
            fdata = _fbi.get(fid, {})
            label = fdata.get("title") or f"AI: {engine_id}"
            cat_id = _cat_for_type("ai_probe").category_id
            action_id = f"action-{engine_id}-{fid}"
            tree_nodes.append({
                "id": f"finding-{fid}",
                "data": {
                    "kind":          "finding",
                    "label":         label,
                    "sub_label":     "ai_probe",
                    "category_id":   cat_id,
                    "finding_id":    fid,
                    "node_id":       f"disc-{fid}",
                    "execute_url":   None,
                    "executed":      False,
                    "guidance_only": False,
                    "action_kind":   "",
                    "finding_type":  "ai_probe",
                },
            })
            tree_nodes.append({
                "id": action_id,
                "data": {
                    "kind":          "action",
                    "label":         label,
                    "sub_label":     engine_id,
                    "action_kind":   engine_id,
                    "finding_id":    fid,
                    "node_id":       action_id,
                    "execute_url":   (
                        f"/api/v1/validation/workspace/investigations/{investigation_id}"
                        f"/finding/{fid}/suggest/{engine_id}/execute"
                    ),
                    "engine_id":     engine_id,
                    "executed":      branch.get("state") not in (None, "pending", "armed"),
                    "guidance_only": False,
                },
            })
            tree_edges.append({
                "id":     f"e-finding-{fid}-{action_id}",
                "source": f"finding-{fid}",
                "target": action_id,
            })

    # Synthesize action nodes for planner-dispatched concept-linked branches that
    # are NOT in the SUGGESTIONS catalog and therefore have no ghost action node.
    # Covers detection-class concepts (CONCEPT-LOGIN-PROTECTION-PROBE, CONCEPT-DEFAULT-CREDS
    # when probe-only, etc.) and any future planner-only concept automatically.
    if planner_branches:
        _rendered_finding_ids = {
            n["data"].get("finding_id", "")
            for n in tree_nodes
            if n.get("data", {}).get("kind") == "finding"
        }
        _existing_action_keys = {
            (n["data"].get("finding_id", ""), n["data"].get("action_kind", ""))
            for n in tree_nodes
            if n.get("data", {}).get("kind") == "action"
        }
        _fbi = findings_by_id or {}
        for _pb in planner_branches:
            _pb_fid = _pb.get("finding_id", "")
            _pb_eid = _pb.get("engine_id", "")
            if not _pb_fid or not _pb_eid:
                continue
            if (_pb_fid, _pb_eid) in _existing_action_keys:
                continue  # already rendered (e.g. from ghost actions)
            _existing_action_keys.add((_pb_fid, _pb_eid))
            _pb_concept = _engine_to_concept.get(_pb_eid, "")
            _pb_action_id = f"action-{_pb_eid}-{_pb_fid}"
            # Human-readable label from concept id or engine id
            _pb_label = (
                _pb_concept.replace("CONCEPT-", "").replace("-", " ").title()
                if _pb_concept else _pb_eid
            )
            # If the finding node doesn't exist yet, synthesize it
            if _pb_fid not in _rendered_finding_ids:
                _rendered_finding_ids.add(_pb_fid)
                _pb_fdata = _fbi.get(_pb_fid, {})
                tree_nodes.append({
                    "id": f"finding-{_pb_fid}",
                    "data": {
                        "kind":          "finding",
                        "label":         _pb_fdata.get("title", "Finding"),
                        "sub_label":     _pb_fdata.get("finding_type", ""),
                        "category_id":   _cat_for_type(_pb_fdata.get("finding_type", "")).category_id,
                        "finding_id":    _pb_fid,
                        "node_id":       f"disc-{_pb_fid}",
                        "execute_url":   None,
                        "executed":      False,
                        "guidance_only": False,
                        "action_kind":   "",
                    },
                })
            tree_nodes.append({
                "id": _pb_action_id,
                "data": {
                    "kind":          "action",
                    "label":         _pb_label,
                    "sub_label":     _pb_eid,
                    "action_kind":   _pb_eid,
                    "finding_id":    _pb_fid,
                    "node_id":       _pb_action_id,
                    "execute_url":   (
                        f"/api/v1/validation/workspace/investigations/{investigation_id}"
                        f"/finding/{_pb_fid}/suggest/{_pb_eid}/execute"
                    ),
                    "concept_id":    _pb_concept,
                    "executed":      _pb.get("state") not in (None, "pending", "armed"),
                    "guidance_only": False,
                },
            })
            tree_edges.append({
                "id":     f"e-planner-{_pb_fid}-{_pb_action_id}",
                "source": f"finding-{_pb_fid}",
                "target": _pb_action_id,
            })

    return {"nodes": tree_nodes, "edges": tree_edges}


_WS_EXECUTE_PREFIX = "/api/v1/validation/workspace"


def _collect_pending_actions(investigation_id: str) -> list[dict]:
    """Return next_actions with inputs from completed execution outcomes.

    Deduplicates by action_kind so each executable card appears at most
    once even if multiple runs emitted it. Callers render these in the
    ActionTray (main workspace area) rather than the side panel.
    """
    from apps.investigation_workspace.execution.runtime import (
        active_runs as _exec_runs,
    )

    actions: list[dict] = []
    seen: set[str] = set()

    for run in _exec_runs(investigation_id):
        # Derive finding_id: explicit field first, then parse disc-{id} parent.
        fid = run.finding_id
        pnid = run.parent_node_id or ""
        if not fid and pnid.startswith("disc-"):
            fid = pnid[len("disc-"):]
        if not fid:
            continue

        for outcome in run.results:
            payload     = outcome.payload or {}
            next_actions = payload.get("next_actions") or []
            for na in next_actions:
                ak     = na.get("action_kind", "")
                inputs = na.get("inputs") or []
                if not ak or not inputs or ak in seen:
                    continue
                seen.add(ak)

                # Build the full execute POST URL.
                qs = ""
                if run.exploit_path_id:
                    qs += f"exploit_path_id={run.exploit_path_id}&"
                qs += f"parent_run_id={run.run_id}"
                exec_url = (
                    f"{_WS_EXECUTE_PREFIX}/investigations/{investigation_id}"
                    f"/finding/{fid}/suggest/{ak}/execute?{qs}"
                )

                actions.append({
                    "action_kind": ak,
                    "label":       na.get("label", ak),
                    "reason":      na.get("reason", ""),
                    "inputs":      inputs,   # [{name, location, placeholder, default}]
                    "execute_url": exec_url,
                })

    return actions


def _view_is_empty(view) -> bool:
    for branch in view.branches:
        if branch.root.children:
            return False
    return True


async def _finalize_conductor_scan(investigation_id: str, success: bool) -> None:
    """Update ScanExecution lifecycle after a Conductor investigation concludes.

    Called via the lifecycle_fn callback passed to kick_off. Looks up the
    passive_probe ScanExecution row for this investigation and marks it
    COMPLETED (or FAILED) with the actual findings count.
    """
    import logging
    from datetime import datetime

    from apps.scanner_orchestration.execution.models import ScanStatus
    from apps.scanner_orchestration.storage.finding_repo import NormalizedFindingRepository
    from apps.scanner_orchestration.storage.scan_repo import ScanRepository

    _logger = logging.getLogger("investigation_workspace.api.routes")
    new_status = ScanStatus.COMPLETED if success else ScanStatus.FAILED
    try:
        async with get_db() as db:
            scan_repo = ScanRepository(db)
            finding_repo = NormalizedFindingRepository(db)
            scans = await scan_repo.list_for_investigation(investigation_id)
            scan = next(
                (s for s in scans if s.scanner_type == "passive_probe" and not s.is_terminal),
                None,
            )
            if scan is None:
                return
            findings = await finding_repo.list_for_investigation(investigation_id, limit=10_000)
            await scan_repo.update_status(
                scan_id=scan.scan_id,
                status=new_status,
                completed_at=datetime.utcnow(),
                findings_count=len(findings),
            )
    except Exception:
        _logger.error(
            "lifecycle: failed to update scan_executions for %s",
            investigation_id,
            exc_info=True,
        )


async def _ensure_bootstrap_running(investigation_id: str, target: str) -> None:
    """Kick off (or no-op rejoin) the bootstrap probe for this investigation.

    Phase 44 — the bootstrap now drives a real passive HTTP probe (see
    apps/investigation_workspace/probe/passive.py). The persist callback
    converts each real FindingEvent (a condition the probe actually
    observed) into a NormalizedFinding insert with real evidence captured
    in raw_data.
    """
    from apps.investigation_workspace.bootstrap.runtime import kick_off
    from apps.investigation_workspace.probe.events import FindingEvent

    async def _persist(evt: FindingEvent) -> str | None:
        """Insert one probe-observed finding into the DB.

        Creates (once per investigation) a ScanExecution record with
        scanner_type='passive_probe' so the finding fits the normal
        pipeline. The probe's real response evidence goes into raw_data.
        """
        from apps.investigation_core.services.investigation_service import (
            InvestigationService,
        )
        from apps.scanner_orchestration.execution.models import (
            ScanExecution,
            ScanStatus,
        )
        from apps.scanner_orchestration.normalization.models import (
            NormalizedFinding,
        )
        from apps.scanner_orchestration.storage.finding_repo import (
            NormalizedFindingRepository,
        )
        from apps.scanner_orchestration.storage.scan_repo import ScanRepository

        async with get_db() as db:
            scan_repo = ScanRepository(db)
            existing = await scan_repo.list_for_investigation(investigation_id)
            scan = next(
                (s for s in existing if s.scanner_type == "passive_probe"),
                None,
            )
            if scan is None:
                scan = ScanExecution(
                    investigation_id = investigation_id,
                    scanner_type     = "passive_probe",
                    target           = target,
                    profile          = "bootstrap_probe",
                    status           = ScanStatus.RUNNING,
                )
                await scan_repo.insert(scan)

            finding = NormalizedFinding(
                finding_id       = (evt.id or str(uuid4())),
                scan_id          = scan.scan_id,
                investigation_id = investigation_id,
                source_scanner   = (evt.source_scanner or "passive_probe"),
                finding_type     = evt.finding_type,
                severity         = evt.severity,
                title            = evt.title,
                description      = evt.description,
                target           = target,
                port             = evt.port,
                endpoint         = evt.endpoint,
                tags             = ["passive_probe", "bootstrap", f"phase:{evt.phase}"],
                raw_data         = {**(evt.evidence or {}), "_phase": evt.phase},
            )
            await NormalizedFindingRepository(db).insert(finding)
            try:
                await InvestigationService(db).record_finding_detected(
                    investigation_id,
                    finding.finding_id,
                    finding.finding_type,
                    finding.severity,
                )
            except Exception:
                pass

        return finding.finding_id

    async def _lifecycle(success: bool) -> None:
        await _finalize_conductor_scan(investigation_id, success)

    await kick_off(
        investigation_id = investigation_id,
        target           = target,
        persist_finding  = _persist,
        lifecycle_fn     = _lifecycle,
    )


@router.get(
    "/investigations/{investigation_id}/context-panel/{node_id}",
    response_class=HTMLResponse,
)
async def context_panel(investigation_id: str, node_id: str, request: Request):
    """Phase 37 — right-side context panel for an Expand'd node.

    Phase 43 — also handles transient pseudo-nodes (bootstrap stages,
    execution stages/results, the waiting marker). Pseudo-nodes are NOT
    in the assembler's view; they're served from the runtime store and
    rendered through partials/context_panel_runtime.html.
    """
    # Pseudo-node ids: boot-{run}-s{i} / exec-{run}-s{i} / exec-{run}-r{j}
    if node_id.startswith(("boot-", "exec-")):
        return await _runtime_context_panel(
            investigation_id, node_id, request,
        )
    if node_id.startswith("path-"):
        # Phase 52 — exploitation-path nodes are synthesized in the
        # topology layer. They aren't BranchNodes; serve them through a
        # registry-backed panel renderer.
        return await _exploitation_path_panel(
            investigation_id, node_id, request,
        )
    if node_id.startswith("bundle-"):
        # Phase 58 — Capture nodes (post-exploit artifact bundles).
        return await _capture_bundle_panel(
            investigation_id, node_id, request,
        )

    from apps.investigation_core.evidence.services.evidence_service import (
        EvidenceService,
    )
    from apps.investigation_core.guided_actions.approvals.approval_service import (
        ApprovalService,
    )
    from apps.investigation_core.guided_actions.models.approval import ApprovalStatus
    from apps.investigation_core.guided_actions.registry.action_registry import (
        action_registry,
    )
    from apps.investigation_core.services.investigation_service import (
        InvestigationService,
    )
    from apps.investigation_workspace.branch.assembler import BranchAssembler
    from apps.investigation_workspace.branch.model import NodeKind

    async with get_db() as db:
        inv = await InvestigationService(db).get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        target = inv.targets[0] if inv.targets else ""
        view = await BranchAssembler(db).assemble(investigation_id, target)

        # Locate the focused node
        focus = None
        for branch in view.branches:
            for n in _walk_view(branch.root):
                if n.node_id == node_id:
                    focus = n
                    break
            if focus:
                break
        if focus is None:
            raise HTTPException(status_code=404, detail="Node not in topology")

        # Pull action + approval state for action/remediation nodes
        action = None
        approval = None
        action_evidence: list = []
        success_indicators: list[str] = []
        if focus.kind in (NodeKind.ACTION, NodeKind.REMEDIATION):
            aid = focus.action_id or focus.remediation_action_id
            if aid:
                action = action_registry.get(aid)
                approval = await ApprovalService(db).get_approval(
                    investigation_id, aid,
                )
                action_evidence = await EvidenceService(db).list_for_guided_action(
                    investigation_id, aid,
                )
                if action:
                    success_indicators = list(getattr(action, "outcome_indicators", None) or [])
                    if not success_indicators and action.steps:
                        success_indicators = [
                            s.expected_result for s in action.steps if s.expected_result
                        ]

    status = str(approval.status) if approval else "none"
    is_action = focus.kind in (NodeKind.ACTION, NodeKind.REMEDIATION)

    # ── Phase 38 — execution-centric fields ──────────────────────────────
    # Deterministically derive what the panel shows: outcome, confidence,
    # generated next branches, related findings. No LLM, no scoring — pure
    # transforms over the BranchNode tree the assembler already built.
    from apps.investigation_workspace.branch.topology_v2 import (
        _STATE_TO_STATUS,
    )
    from apps.investigation_workspace.execution.runtime import (
        has_been_executed,
        latest_run_for_action,
    )

    # Phase 39 — operational runtime overlay. If this node has a live (or
    # recently completed) execution run, prefer its stage/result labels
    # over the static narrative so the panel reads as a runtime, not a
    # textbook.
    run = None
    if is_action and action:
        run = latest_run_for_action(investigation_id, action.action_id)

    # Outcome summary — drawn from approval state + outcome_indicators.
    if status == "completed":
        outcome_kind = "verified"
        outcome_summary = (
            success_indicators[0] if success_indicators
            else (action.title + " — executed" if action else "Verified.")
        )
    elif status == "approved":
        outcome_kind = "running"
        outcome_summary = "Execution in progress."
    elif status == "rejected":
        outcome_kind = "rejected"
        outcome_summary = "Rejected by operator."
    else:
        outcome_kind = "pending"
        outcome_summary = ""

    # Generated next branches — direct children of the focused node, with
    # the same status vocabulary the topology uses so the panel reads
    # consistently with the canvas.
    next_branches = [
        {
            "node_id": c.node_id,
            "label":   c.label,
            "status":  _STATE_TO_STATUS.get(c.state, "ready"),
            "kind":    str(c.kind),
        }
        for c in (focus.children or [])
    ]

    # Related findings — other nodes referencing the same finding_id. Skip
    # the focus itself and its descendants (those are already on the path).
    descendant_ids: set[str] = set()
    def _collect(n):
        descendant_ids.add(n.node_id)
        for c in n.children:
            _collect(c)
    _collect(focus)

    related_findings: list[dict] = []
    fid = getattr(focus, "finding_id", None)
    if fid:
        async with get_db() as db:
            # Re-resolve view to walk all branches — we lost the outer view
            # when the first `async with` closed. Cheap on a single-target
            # investigation; the assembler is already idempotent.
            view2 = await BranchAssembler(db).assemble(investigation_id, target)
        for branch in view2.branches:
            for n in _walk_view(branch.root):
                if n.node_id in descendant_ids:
                    continue
                if getattr(n, "finding_id", None) == fid:
                    related_findings.append({
                        "node_id": n.node_id,
                        "label":   n.label,
                        "kind":    str(n.kind),
                        "status":  _STATE_TO_STATUS.get(n.state, "ready"),
                    })
                    if len(related_findings) >= 5:
                        break
            if len(related_findings) >= 5:
                break

    # Phase 39 — operational runtime stage + result lines for the panel.
    runtime_stages: list[dict] = []
    runtime_results: list[dict] = []
    if run is not None:
        for stage in run.stages:
            runtime_stages.append({
                "label":    stage.label,
                "complete": stage.completed_at is not None,
            })
        for r in run.results:
            runtime_results.append({"label": r.label, "kind": r.kind})

    # Phase 45 — suggested next actions for finding-kind nodes. The catalog
    # is deterministic; same finding_type always offers the same actions.
    # Phase 59b — suggestions split into two lists:
    #   automated_suggestions: real probe-backed entries (Execute button)
    #   guidance_suggestions:  guidance_only entries (no Execute button)
    # Phase C-2 — when SELECTION_CARD_ENABLED, also build VaultSelector options.
    automated_suggestions: list[dict] = []
    guidance_suggestions:  list[dict] = []
    selection_options: list = []
    preselect: int | None = None
    finding_display_title: str = ""
    finding_endpoint_display: str = ""
    finding_type_label: str = ""
    ftype: str = ""
    from apps.conductor.constants import SELECTION_CARD_ENABLED, SIM_FLOOR as _SIM_FLOOR
    selection_card_enabled: bool = SELECTION_CARD_ENABLED

    # Phase C-3: check if a session has been captured for this investigation.
    # Used by the selection card to update the js_spider "requires session" badge.
    session_available: bool = False
    try:
        from apps.conductor.exploitation.branch_store import BranchReader as _BR
        _branches = await _BR().list_for_investigation(investigation_id)
        session_available = any(
            b.state == "succeeded" and b.artifact_type == "captured_session"
            for b in _branches
        )
    except Exception:
        pass

    if focus.kind == NodeKind.DISCOVERY and fid:
        from apps.investigation_workspace.suggestions.catalog import (
            for_finding_type,
        )
        from apps.scanner_orchestration.storage.finding_repo import (
            NormalizedFindingRepository,
        )
        async with get_db() as db:
            f = await NormalizedFindingRepository(db).get_by_id(fid)
        ftype = getattr(f, "finding_type", "") if f else ""
        finding_display_title   = getattr(f, "title", "") if f else ""
        finding_endpoint_display = getattr(f, "endpoint", "") or ""
        finding_type_label = ftype.replace("_", " ").title() if ftype else ""

        for spec in for_finding_type(ftype):
            entry = {
                "action_kind": spec.action_kind,
                "label":       spec.label,
                "reasoning":   spec.reasoning,
                "executed":    has_been_executed(investigation_id, fid, spec.action_kind),
            }
            if spec.guidance_only:
                guidance_suggestions.append(entry)
            else:
                automated_suggestions.append(entry)

        # Phase C-2 — VaultSelector: vault-ranked + SUGGESTIONS floor merged.
        if selection_card_enabled:
            try:
                from apps.conductor.vault_selector import (
                    merge_with_floor,
                    rank_techniques,
                    suggestions_floor,
                )
                _vault = await rank_techniques(
                    ftype,
                    finding_display_title,
                    finding_endpoint_display or None,
                )
                _floor = suggestions_floor(ftype)
                selection_options = merge_with_floor(_vault, _floor)

                # V3.1 Part A2 — Orchestrated AI ranking (gated, off hot path).
                # Fires at most ONCE per card build, only when:
                #   - 2+ candidates with engine_ids exist (single obvious → no model)
                #   - objective text or recent results are available (context to read)
                # Model reorders the deterministic Part A list — never invents engine_ids.
                # Stage 3 (deterministic) validates: invalid permutation → unchanged.
                # Falls back to deterministic order on any failure (Ollama down → still works).
                _a2_ranking_applied = False
                try:
                    from apps.conductor.investigation_state import load_state_async
                    _inv_state_a2 = await load_state_async(investigation_id)
                    _objective_text = _inv_state_a2.objective or None
                    _recent_results = [
                        a.get("technique_title", a.get("engine_id", ""))
                        for a in _inv_state_a2.attempt_tree[-3:]
                        if a.get("status") in ("exhausted", "fail", "success")
                    ]
                    _actionable = [o for o in selection_options if o.engine_id]
                    _needs_ranking = (
                        len(_actionable) >= 2
                        and (_objective_text or _recent_results)
                    )
                    if _needs_ranking:
                        # V3.1 deterministic override: objective names ONE technology →
                        # zero model calls, guaranteed correct ranking.
                        # Falls back to model A2 when objective is ambiguous or absent.
                        from apps.conductor.vault_selector import objective_tech_override
                        _det_reordered, _det_applied = objective_tech_override(
                            _objective_text, selection_options
                        )
                        if _det_applied:
                            selection_options = _det_reordered
                            _a2_ranking_applied = True
                            _routes_logging.getLogger("routes.context_panel").info(
                                "objective_tech_override applied for %s/%s (0 model calls)",
                                investigation_id, fid,
                            )
                        else:
                            # Ambiguous or no tech keyword → model A2 (2 Ollama calls)
                            from apps.conductor.model_advisor import rank_candidates_with_context
                            _reordered = await rank_candidates_with_context(
                                finding_type   = ftype,
                                finding_title  = finding_display_title,
                                candidates     = selection_options,
                                objective      = _objective_text,
                                recent_results = _recent_results,
                            )
                            if _reordered is not selection_options:
                                selection_options = _reordered
                                _a2_ranking_applied = True
                                _routes_logging.getLogger("routes.context_panel").info(
                                    "A2 ranking applied for %s/%s", investigation_id, fid
                                )
                    # Persist ranked order into InvestigationState for Part C fallback
                    _ranked_eids = [o.engine_id for o in selection_options if o.engine_id]
                    if _ranked_eids and fid:
                        _inv_state_a2.ranked_lists[fid] = _ranked_eids
                        from apps.conductor.investigation_state import save_state_async
                        await save_state_async(_inv_state_a2)
                except Exception as _a2_exc:
                    _routes_logging.getLogger("routes.context_panel").debug(
                        "A2 ranking skipped: %s", _a2_exc
                    )

                # Phase 1: AI is the PRIMARY DRIVER when an objective is present.
                # The vault ranking (selection_options) and A2 reordering feed the AI as
                # CONTEXT (via package_findings_context.vault_candidates), NOT as the
                # final answer. The AI selects from the manifest's applicable primitives;
                # the vault ranking informs that choice.
                #
                # When no objective is set: fall back to deterministic ranking (SIM_FLOOR gate).
                # This preserves the C6 invariant: operator always executes; AI decides.
                # POST-execution D2 (in result_zone handler) is a SEPARATE path — untouched.
                _wo_added = False
                if _inv_state_a2.objective and fid:
                    # Planner-driven proposal — plan_next_step() is the ONE selection authority.
                    # generate_work_order (AI selection) is removed from this path.
                    # If agent_state is absent/uninitialized: _wo_added stays False →
                    # falls through to deterministic vault ranking (no AI fallback).
                    try:
                        import uuid as _p1_uuid
                        from apps.conductor.planner import plan_next_step as _p1_plan
                        from apps.conductor.agent_state import (
                            load_agent_state_async as _p1_load_as,
                        )
                        from apps.conductor.model_advisor import WorkOrder as _P1WorkOrder
                        from apps.conductor.vault_selector import TechniqueOption as _P1TO
                        from apps.conductor.investigation_state import save_state_async as _save_wo

                        _p1_as = await _p1_load_as(investigation_id)
                        if _p1_as and "goal" in _p1_as:
                            _p1_dec = _p1_plan(_p1_as)
                            if _p1_dec.action == "execute" and _p1_dec.engine_id:
                                _wo = _P1WorkOrder(
                                    id           = str(_p1_uuid.uuid4()),
                                    primitive_id = _p1_dec.engine_id,
                                    engine_id    = _p1_dec.engine_id,
                                    params       = {"concept_id": _p1_dec.concept_id},
                                    rationale    = _p1_dec.log_entry,
                                    finding_id   = fid,
                                    source       = "planner",
                                )
                                # Store for execute route lookup (work_order_id param)
                                _inv_state_a2.pending_work_orders[_wo.id] = {
                                    "id":           _wo.id,
                                    "primitive_id": _wo.primitive_id,
                                    "engine_id":    _wo.engine_id,
                                    "params":       _wo.params,
                                    "rationale":    _wo.rationale,
                                    "finding_id":   _wo.finding_id,
                                }
                                await _save_wo(_inv_state_a2)
                                # Build TechniqueOption with planner badge + deterministic reason
                                _wo_option = _P1TO(
                                    concept_id                 = _p1_dec.concept_id,
                                    engine_id                  = _p1_dec.engine_id,
                                    title                      = (
                                        f"[Planner] {_p1_dec.engine_id}"
                                        f" — {_p1_dec.reason[:60]}"
                                    ),
                                    similarity                 = 0.0,
                                    requires_session           = False,
                                    source                     = "work_order",
                                    method                     = None,
                                    endpoint_hint              = None,
                                    payload_template_available = False,
                                    already_attempted          = False,
                                    work_order_id              = _wo.id,
                                )
                                _deduped = [
                                    o for o in selection_options
                                    if o.engine_id != _wo.engine_id
                                ]
                                selection_options = [_wo_option] + _deduped
                                preselect = 0
                                _wo_added = True
                                _routes_logging.getLogger("routes.context_panel").info(
                                    "Planner driver: selected %r (priority=%d concept=%s)"
                                    " for %s/%s",
                                    _p1_dec.engine_id, _p1_dec.priority,
                                    _p1_dec.concept_id, investigation_id, fid,
                                )
                    except Exception as _wo_exc:
                        _routes_logging.getLogger("routes.context_panel").debug(
                            "Planner driver failed for %s/%s: %s",
                            investigation_id, fid, _wo_exc,
                        )

                # Fallback when no objective or AI driver failed:
                # deterministic ranking (SIM_FLOOR + A2) is the decider.
                if not _wo_added:
                    if _a2_ranking_applied:
                        preselect = 0       # A2 reordering applied — preselect its top
                    elif selection_options and selection_options[0].similarity >= _SIM_FLOOR:
                        preselect = 0       # vault semantically confident — preselect top
                    else:
                        preselect = None    # vault not confident, no objective → D2 fallback
                        try:
                            from apps.conductor.model_advisor import advise_next_step
                            _model_suggestion = await advise_next_step(
                                session=None,
                                technique_used=None,
                                parsed_result=None,
                                vault_context=selection_options,
                            )
                            if _model_suggestion:
                                selection_options = list(selection_options) + [_model_suggestion]
                        except Exception as _madv_exc:
                            _routes_logging.getLogger("routes.context_panel").debug(
                                "model_advisor D2 skipped: %s", _madv_exc
                            )
            except Exception as _vsel_exc:
                _routes_logging.getLogger("routes.context_panel").warning(
                    "VaultSelector failed for %s/%s: %s", investigation_id, fid, _vsel_exc
                )

        # Phase E Part 3 / Part C — mark already-attempted engines + compute fallback preselect
        all_techniques_tried: bool = False
        if selection_options and fid:
            try:
                from apps.conductor.investigation_state import load_state_async
                _inv_state = await load_state_async(investigation_id)
                _tried = {
                    a["engine_id"]
                    for a in _inv_state.attempt_tree
                    if a.get("finding_id") == fid
                }
                if _tried:
                    selection_options = [
                        type(o)(
                            concept_id                = o.concept_id,
                            engine_id                 = o.engine_id,
                            title                     = o.title,
                            similarity                = o.similarity,
                            requires_session          = o.requires_session,
                            source                    = o.source,
                            method                    = o.method,
                            endpoint_hint             = o.endpoint_hint,
                            payload_template_available= o.payload_template_available,
                            already_attempted         = o.engine_id in _tried,
                        )
                        for o in selection_options
                    ]
                    # Part C — fallback preselect: first untried option in ranked order
                    untried = [i for i, o in enumerate(selection_options)
                               if o.engine_id and not o.already_attempted]
                    if untried:
                        preselect = untried[0]  # advance to next untried
                    else:
                        # All ranked techniques tried — show "all tried" state
                        preselect = None
                        all_techniques_tried = True
            except Exception:
                pass

    response = templates.TemplateResponse(
        "partials/context_panel.html",
        {
            "request":            request,
            "investigation_id":   investigation_id,
            "node":               focus,
            "action":             action,
            "approval":           approval,
            "action_evidence":    action_evidence,
            "evidence_count":     len(action_evidence),
            "success_indicators": success_indicators,
            "approval_status":    status,
            "is_action":          is_action,
            "ApprovalStatus":     ApprovalStatus,
            # Phase 38 — execution-centric additions
            "outcome_summary":    outcome_summary,
            "outcome_kind":       outcome_kind,
            "next_branches":      next_branches,
            "related_findings":   related_findings,
            "confidence_glyph":   getattr(focus, "confidence_glyph", ""),
            "confidence_label":   getattr(focus, "confidence_label", ""),
            # Phase 39 — live runtime
            "runtime_stages":     runtime_stages,
            "runtime_results":    runtime_results,
            "has_run":            run is not None,
            # Phase 45 + 59b — operator-guided branching, split between
            # real probe-backed automated actions and guidance-only manual
            # investigation paths.
            "automated_suggestions":   automated_suggestions,
            "guidance_suggestions":    guidance_suggestions,
            "finding_id":              fid or "",
            # Phase C-2 — VaultSelector selection card
            "selection_card_enabled":   selection_card_enabled,
            "selection_options":        selection_options,
            "preselect":                preselect,
            "all_techniques_tried":     all_techniques_tried,
            # execute_disabled: computed in Python so the template never needs
            # an inline ternary (Jinja2 does not support Python's `x if c else y`
            # inside {%if%} expressions — see docs/ui-verification-playbook.md).
            "execute_disabled": (
                preselect is None
                or (bool(selection_options) and selection_options[preselect].engine_id is None)
            ),
            "finding_type_label":       finding_type_label,
            "finding_display_title":    finding_display_title,
            "finding_endpoint_display": finding_endpoint_display,
            "session_available":        session_available,
        },
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


def _walk_view(node):
    yield node
    for c in node.children:
        yield from _walk_view(c)


# ── Phase 45 — operator-guided suggestion execution ────────────────────

# Action kinds that require ?confirm=<action_kind> on the POST request.
# This is a runtime gate — the UI already implements the arm/confirm pattern;
# this server-side check prevents direct API calls from bypassing it.
_EXPLOITATION_ACTIONS: frozenset[str] = frozenset({
    # V2 engine-dispatched exploitation actions (arm gate; C6: no system gate_id)
    "xss_reflect",
    "credential_brute",
    "cmdi_reflected",
    "cmdi_blind_time",
    "cmdi_blind_boolean",
    "sqli_auth_bypass",
    "default_creds",
    "access_control",
    "metasploit_recipe",
})


@router.post(
    "/investigations/{investigation_id}/finding/{finding_id}/suggest/{action_kind}/execute",
    response_class=HTMLResponse,
)
async def execute_suggestion(
    investigation_id: str,
    finding_id:       str,
    action_kind:      str,
    request:          Request,
    exploit_path_id:  str = "",
    parent_run_id:    str = "",
    confirm:          str = "",
    concept_id:       str = "",   # concept_id thread-through (Fix: operator selection → engine)
    work_order_id:    str = "",   # Bundle 2: AI work order ID (look up from InvestigationState)
):
    """Execute one operator-approved suggested action against a finding.

    Looks up the SuggestionSpec by action_kind, then fires an
    execution_runtime run anchored at the finding's topology node. The
    run's reasoning stages animate and produce result nodes as part of
    the persistent investigation lineage.

    The endpoint is the operator's explicit choice — branches only grow
    when the operator clicks Execute on one suggestion. No auto-spawn.

    Phase 54b — `exploit_path_id` (optional query param) is the
    exploitation_path the operator clicked FROM (ghost node on the graph
    or button in the structured-evidence panel). When provided, it's
    stored on the ExecutionRun so ghost emission can attribute new
    ghosts to the right path without the action_kind reverse-lookup.
    Absent for legacy callers (Phase 45 suggestion panel that doesn't
    yet carry path context).
    """
    from apps.investigation_workspace.execution.runtime import (
        kick_off as exec_kick_off,
    )
    from apps.investigation_workspace.suggestions.catalog import find_spec
    from apps.scanner_orchestration.storage.finding_repo import (
        NormalizedFindingRepository,
    )

    spec = find_spec(action_kind)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"Unknown action_kind: {action_kind}")

    async with get_db() as db:
        finding = await NormalizedFindingRepository(db).get_by_id(finding_id)
    if not finding or finding.investigation_id != investigation_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    # The execution overlay normally anchors on the finding's discovery node.
    # When parent_run_id is provided (mutate cards in the IDOR result panel),
    # anchor under that run's first result node so the mutate run shows as a
    # grandchild of the IDOR confirmation in the mind map.
    parent_node_id = (
        f"exec-{parent_run_id}-r0" if parent_run_id
        else f"disc-{finding_id}"
    )

    # Phase 46 — propagate canonical target through the execution kick_off
    # so future real-HTTP execution scripts cannot derive a URL from any
    # other source.
    from apps.investigation_core.services.investigation_service import (
        InvestigationService,
    )
    async with get_db() as db:
        inv = await InvestigationService(db).get_by_id(investigation_id)
    canonical_target = inv.targets[0] if inv and inv.targets else ""

    # Phase 57 — idempotent kick_off. Dedup key is
    # (finding_id, action_kind, exploit_path_id). A second click while
    # the first run is still active returns the same run_id silently.
    # Same action_kind under two different exploit paths on the same
    # finding is NOT a duplicate — both runs proceed.
    dedup_key = (finding_id, action_kind, exploit_path_id or "")

    # V2 engine dispatch — engine_id set means route via Conductor instead of probe.
    if spec.engine_id is not None:
        from apps.conductor.shared import get_shared_conductor
        _conductor = get_shared_conductor()
        _ctx = _conductor.get_context(investigation_id)

        # Read extended_payloads and qwen_triggered from request body if JSON.
        # Must happen before the _ctx is None check so _qwen_triggered is known
        # when deciding whether to reconstruct a missing context.
        _extended_payloads: list = []
        _qwen_triggered: bool = False
        _qwen_reason: str = ""
        _ai_finding_id: str = finding_id  # default: use URL finding_id
        _op_params: dict = {}   # operator_params from request body (incl. self_pass when present)
        try:
            _content_type = request.headers.get("content-type", "")
            if "application/json" in _content_type:
                _body = await request.json()
                _extended_payloads = _body.get("extended_payloads", [])
                _qwen_triggered = bool(_body.get("qwen_triggered", False))
                _qwen_reason = str(_body.get("qwen_reason", "")).strip()[:200]
                _op_params = dict(_body.get("operator_params") or {})
        except Exception:
            pass

        if _ctx is None:
            if _qwen_triggered:
                # Reconstruct a minimal conductor context so Qwen-triggered
                # probes work before any engine has run or after container
                # restart (when _active is empty).
                try:
                    from apps.conductor.conductor import _InvestigationContext
                    _recon_config: dict = {}
                    try:
                        _recon_row = _conductor._db.execute(
                            "SELECT config_json FROM investigations WHERE id=?",
                            (investigation_id,),
                        ).fetchone()
                        if _recon_row and _recon_row[0]:
                            _recon_config = json.loads(_recon_row[0])
                    except Exception:
                        pass
                    _ctx = _InvestigationContext(
                        investigation_id=investigation_id,
                        target=canonical_target,
                        config=_recon_config,
                        bus=_conductor._bus,
                        db_path=_conductor._db_path,
                    )
                    _conductor._active[investigation_id] = _ctx
                    await _ctx.exec_orch.start_health_monitor()
                    # Session Unification: rehydrate the fresh SessionOrchestrator
                    # from the durable InvestigationState.captured_session record so
                    # engines see the previously-captured session after reconstruction.
                    try:
                        from apps.conductor.session_persistence import rehydrate_session
                        await rehydrate_session(_ctx.session_orch, investigation_id)
                    except Exception as _reh_exc:
                        _routes_logging.getLogger("routes.execute_suggestion").debug(
                            "session rehydration failed (non-fatal): %s", _reh_exc
                        )
                except Exception as _recon_exc:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"No active conductor context for {investigation_id} "
                            f"and reconstruction failed: {_recon_exc}"
                        ),
                    )
            else:
                raise HTTPException(
                    status_code=409,
                    detail=f"No active investigation context for {investigation_id}",
                )

        # Qwen-triggered dispatch: create a synthetic ai_probe finding so the
        # engine branch renders as its own root node in the mindmap.
        if _qwen_triggered and _extended_payloads:
            import logging as _logging
            from uuid import uuid4 as _uuid4
            from datetime import datetime as _dt, timezone as _tz
            _ailog = _logging.getLogger("investigation_workspace.api.routes.ai_probe")
            _ai_finding_id = f"fnd_ai_{_uuid4().hex[:8]}"
            _ai_title = f"AI: {_qwen_reason}" if _qwen_reason else f"AI: {action_kind}"
            _ailog.info(
                "ai_probe INSERT: finding_id=%s investigation_id=%s title=%r",
                _ai_finding_id, investigation_id, _ai_title,
            )
            async with get_db() as _db:
                # normalized_findings.scan_id is NOT NULL — reuse an existing
                # scan_id for this investigation; create a minimal scan_execution
                # row if this is the first finding (e.g., investigation started
                # without a scanner run).
                _sc = await _db.execute(
                    "SELECT scan_id FROM normalized_findings "
                    "WHERE investigation_id=? LIMIT 1",
                    (investigation_id,),
                )
                _scan_row = await _sc.fetchone()
                if _scan_row:
                    _ai_scan_id = _scan_row[0]
                else:
                    _ai_scan_id = str(_uuid4())
                    _now = _dt.now(_tz.utc).isoformat()
                    await _db.execute(
                        """INSERT OR IGNORE INTO scan_executions
                           (scan_id, investigation_id, scanner_type, target, created_at)
                           VALUES (?, ?, 'qwen', ?, ?)""",
                        (_ai_scan_id, investigation_id, canonical_target, _now),
                    )
                _ailog.info(
                    "ai_probe INSERT: using scan_id=%s", _ai_scan_id,
                )
                _cur = await _db.execute(
                    """INSERT OR IGNORE INTO normalized_findings
                       (finding_id, scan_id, investigation_id, source_scanner,
                        finding_type, severity, title, description, target, port, endpoint,
                        evidence_refs, related_cves, related_cwes, tags, raw_data, created_at)
                       VALUES (?, ?, ?, 'qwen', 'ai_probe', 'info', ?, '', ?, NULL, '/',
                               '[]', '[]', '[]', '[]', '{}', ?)""",
                    (
                        _ai_finding_id,
                        _ai_scan_id,
                        investigation_id,
                        _ai_title,
                        canonical_target,
                        _dt.now(_tz.utc).isoformat(),
                    ),
                )
                await _db.commit()
                _ailog.info(
                    "ai_probe INSERT complete: rowcount=%s finding_id=%s",
                    _cur.rowcount, _ai_finding_id,
                )
            finding_id = _ai_finding_id  # use ai finding as parent

        # Thread the operator's selected concept_id so GenericHTTPEngine
        # uses the correct EXEC-TEMPLATE (not its construction-time default).
        # Specialized engines ignore concept_id harmlessly (they don't read templates).
        _extra: dict = {}
        if concept_id:
            _extra["concept_id"] = concept_id
        if _extended_payloads:
            _extra["extended_payloads"]  = _extended_payloads
            _extra["qwen_finding_id"]    = _ai_finding_id

        # Thread operator_params from request body into extra_config.
        # self_pass (and other operator-supplied params) are threaded here at dispatch time —
        # they are NEVER stored in pending_work_orders or agent_state (self_pass invariant).
        if _op_params:
            for _opk, _opv in _op_params.items():
                if _opk not in _extra:
                    _extra[_opk] = _opv

        # Bundle 2: merge work-order params (strategy, target_account, etc.) when present.
        # Work-order params (stored at proposal time) do not contain self_pass.
        if work_order_id:
            try:
                from apps.conductor.investigation_state import load_state_async as _load_wo_state
                _wo_state = await _load_wo_state(investigation_id)
                _wo_dict  = _wo_state.pending_work_orders.get(work_order_id)
                if _wo_dict:
                    _wo_params = dict(_wo_dict.get("params", {}))
                    # Work order params fill _extra (concept_id already set above takes precedence)
                    for _k, _v in _wo_params.items():
                        if _k not in _extra and _v:
                            _extra[_k] = _v
                    _routes_logging.getLogger("routes.execute_suggestion").info(
                        "work_order params merged: primitive=%r extra_keys=%r",
                        _wo_dict.get("primitive_id"), list(_wo_params.keys()),
                    )
            except Exception as _wo_exec_exc:
                _routes_logging.getLogger("routes.execute_suggestion").debug(
                    "work_order param merge failed: %s", _wo_exec_exc
                )

        # ── DIAGNOSTIC INSTRUMENTATION (log-only, no logic change) ─────────
        import time as _diag_t2
        _diag_log2 = _routes_logging.getLogger("routes.execute_suggestion.DIAG")
        _exec_id2       = id(_ctx.exec_orch)
        _cancelled2     = getattr(_ctx.exec_orch, "_cancelled", None)
        _running_keys2  = list(getattr(_ctx.exec_orch, "_running", {}).keys())
        _diag_log2.info(
            "DIAG execute_suggestion [EXECUTE PATH] inv=%s engine=%s finding=%s | "
            "exec_id=%s executor_cancelled=%s running_keys=%s",
            investigation_id, spec.engine_id, finding_id,
            _exec_id2, _cancelled2, _running_keys2,
        )
        # ── END DIAGNOSTIC ────────────────────────────────────────────────────
        _running_before_exec = set(getattr(_ctx.exec_orch, "_running", {}).keys())

        await _ctx.exec_orch.dispatch_engine(
            spec.engine_id,
            correlation_id=finding_id,
            extra_config=_extra or None,
        )

        _running_after_exec = set(getattr(_ctx.exec_orch, "_running", {}).keys())
        _new_run_ids_exec = _running_after_exec - _running_before_exec
        _diag_log2.info(
            "DIAG execute_suggestion [POST-DISPATCH] inv=%s engine=%s | "
            "launch_fired=%s new_run_ids=%s executor_cancelled_after=%s",
            investigation_id, spec.engine_id,
            bool(_new_run_ids_exec), list(_new_run_ids_exec),
            getattr(_ctx.exec_orch, "_cancelled", None),
        )
        # ── END DIAGNOSTIC ────────────────────────────────────────────────────

        # Phase C-3 — return a "running" Zone 3 partial that polls for the result.
        # The engine runs asynchronously; Zone 3 polls GET /result-zone/{finding_id}
        # every 3s until the branch transitions to a terminal state.
        _poll_url = (
            f"/api/v1/validation/workspace/investigations/{investigation_id}"
            f"/result-zone/{finding_id}"
        )
        _running_html = (
            f'<div id="result-zone-{finding_id}" style="min-height:48px;" '
            f'class="rounded-md border border-dashed border-[#d0d7de] '
            f'px-2 py-1.5 text-[10px] text-zinc-400" '
            f'hx-get="{_poll_url}" hx-trigger="every 3s" hx-swap="outerHTML">'
            f'<span style="animation:invSuggestedPulse 1.2s ease-in-out infinite;'
            f'display:inline-block;">&#x25B8;</span> '
            f'{spec.engine_id} running…'
            f'</div>'
        )
        return HTMLResponse(
            content=_running_html,
            status_code=200,
            headers={
                "HX-Trigger": "reload-branches",
                "X-Run-Id":   f"engine:{spec.engine_id}:{finding_id}",
            },
        )

    # Phase 59b — only real probe-backed suggestions are executable.
    # Guidance-only specs (probe_runner=None) cannot reach this path
    # because the panel doesn't render Execute buttons for them; if
    # someone POSTs directly anyway, reject with a clear error.
    if spec.probe_runner is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Action '{action_kind}' is guidance-only — no probe is "
                "registered. The operator should run the technique manually."
            ),
        )

    # Exploitation-phase actions require an explicit ?confirm=<action_kind> to
    # prevent accidental firing via direct API calls or UI mis-clicks.
    # Dynamic action_kinds (api_method_*) are matched by prefix.
    _needs_confirm = (
        action_kind in _EXPLOITATION_ACTIONS
        or action_kind.startswith("api_method_")
    )
    if _needs_confirm and confirm != action_kind:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Action '{action_kind}' requires explicit confirmation. "
                f"Re-submit with ?confirm={action_kind}"
            ),
        )

    # Publish operator-supplied form fields so probes can read them via
    # OPERATOR_INPUTS_CTX without changing probe function signatures.
    # asyncio.create_task inherits the current context, propagating values.
    from apps.investigation_workspace.execution.runtime import (
        OPERATOR_INPUTS_CTX as _OPERATOR_INPUTS_CTX,
    )
    _form = await request.form()
    _OPERATOR_INPUTS_CTX.set(dict(_form))

    run = await exec_kick_off(
        investigation_id = investigation_id,
        action_id        = f"suggestion:{action_kind}",
        parent_node_id   = parent_node_id,
        probe_runner     = spec.probe_runner,
        on_complete      = None,
        exploit_path_id  = exploit_path_id or None,
        canonical_target = canonical_target,
        dedup_key        = dedup_key,
        finding_id       = finding_id,
    )
    # Operator never sees a "duplicate suppressed" notification; the
    # response is identical whether the run is fresh or de-dup'd. The
    # X-Run-Id header surfaces the run_id for tests / log correlation.
    return HTMLResponse(
        content="",
        status_code=200,
        headers={
            "HX-Trigger": "reload-branches",
            "X-Run-Id":   run.run_id,
        },
    )


# ── Phase C-3 — result zone polling endpoint ─────────────────────────────────


@router.get(
    "/investigations/{investigation_id}/result-zone/{finding_id}",
    response_class=HTMLResponse,
)
async def result_zone(investigation_id: str, finding_id: str, request: Request):
    """Return structured Zone 3 HTML for the given finding.

    Polls exploitation_branches for the most recent terminal branch on this
    finding. Returns:
      - _result_zone.html (final) when state is succeeded or exhausted
      - inline "running" HTML with hx-trigger polling when still in-flight
    """
    from apps.conductor.exploitation.branch_store import BranchReader
    from apps.conductor.result_parser import parse_engine_result
    from apps.conductor.vault_selector import rank_techniques

    reader  = BranchReader()
    records = await reader.list_for_finding(finding_id)

    # Find the most recent terminal branch for this finding
    terminal = None
    for r in sorted(records, key=lambda x: x.updated_at or "", reverse=True):
        if r.state in ("succeeded", "exhausted", "failed"):
            terminal = r
            break

    if terminal is None:
        # Still running — return same polling div so htmx keeps polling.
        # For oracle_search, surface extraction progress from the stage_log.
        _poll_url = (
            f"/api/v1/validation/workspace/investigations/{investigation_id}"
            f"/result-zone/{finding_id}"
        )
        _engine_label = records[0].engine_id if records else "engine"
        _progress_msg = ""
        if records and _engine_label == "oracle_search":
            try:
                for _entry in reversed(records[0].stage_log or []):
                    _prog = _entry.get("extraction_progress") if isinstance(_entry, dict) else None
                    if _prog and isinstance(_prog, dict):
                        _pos = _prog.get("position", 0)
                        _len = _prog.get("length")
                        _pfx = _prog.get("prefix", "")
                        if _len and _pos:
                            _progress_msg = (
                                f" — {_pos}/{_len}: '{_pfx}…'"
                                if _pfx else f" — position {_pos}/{_len}"
                            )
                        elif _pfx:
                            _progress_msg = f" — '{_pfx}…'"
                        break
            except Exception:
                pass
        _running = (
            f'<div id="result-zone-{finding_id}" style="min-height:48px;" '
            f'class="rounded-md border border-dashed border-[#d0d7de] '
            f'px-2 py-1.5 text-[10px] text-zinc-400" '
            f'hx-get="{_poll_url}" hx-trigger="every 3s" hx-swap="outerHTML">'
            f'<span style="animation:invSuggestedPulse 1.2s ease-in-out infinite;'
            f'display:inline-block;">&#x25B8;</span> '
            f'{_engine_label} running…{_progress_msg}'
            f'</div>'
        )
        return HTMLResponse(content=_running)

    parsed = parse_engine_result(
        engine_id=terminal.engine_id,
        artifact=terminal.artifact,
        exhaustion_record=terminal.exhaustion_record,
        state=terminal.state,
    )

    # "What's next?" — vault suggestion using parsed summary as extra context
    next_options: list = []
    model_advice = None
    ftype, ftitle = "", ""
    try:
        # Look up the finding title from normalized_findings for a richer query
        async with get_db() as db:
            row = await db.execute(
                "SELECT finding_type, title FROM normalized_findings WHERE finding_id=?",
                (finding_id,),
            )
            frow = await row.fetchone()
        if frow:
            ftype, ftitle = frow[0] or "", frow[1] or ""
            vault_hits = await rank_techniques(
                finding_type=ftype,
                finding_title=f"{ftitle} — {parsed.summary}",
                top_k=3,
            )
            # Filter out the engine just executed and advisory-only options
            already_ran = terminal.engine_id
            next_options = [
                o for o in vault_hits
                if o.engine_id and o.engine_id != already_ran
            ][:2]
    except Exception:
        pass

    # Phase D2 — post-execution model advisor (called only on meaningful results)
    if parsed.status in ("success", "partial"):
        try:
            from apps.conductor.model_advisor import advise_next_step
            session_data = parsed.session_data if parsed.session_captured else None
            model_advice = await advise_next_step(
                session=session_data,
                technique_used=terminal.engine_id,
                parsed_result=parsed,
                vault_context=next_options,
            )
        except Exception as _madv_exc:
            _routes_logging.getLogger("routes.result_zone").debug(
                "post-execution model_advisor skipped: %s", _madv_exc
            )

    # Phase E Part 3 — update attempt_tree in investigation state
    try:
        from apps.conductor.investigation_state import load_state_async, save_state_async
        _state = await load_state_async(investigation_id)
        _state.attempt_tree.append({
            "engine_id":       terminal.engine_id,
            "finding_id":      finding_id,
            "status":          parsed.status,
            "parent_id":       None,
            "technique_title": terminal.engine_id,
        })
        if parsed.session_captured and parsed.session_data:
            _state.session = parsed.session_data
        await save_state_async(_state)
    except Exception as _state_exc:
        _routes_logging.getLogger("routes.result_zone").debug(
            "investigation_state update failed: %s", _state_exc
        )

    # Phase E Part 1 — load payload variants for Layer 3 iteration.
    # Prefer concept_id stored in the artifact (GenericHTTPEngine stores
    # effective_concept_id there), falling back to the engine_to_concept
    # reverse lookup. This ensures the NoSQL extraction variant appears when
    # access_control ran with CONCEPT-NOSQL-INJECTION (not CONCEPT-ACCESS-CONTROL).
    payload_variants: list = []
    concept_id_for_variants = ""
    if parsed.status in ("success", "partial"):
        try:
            import json as _json_local
            from apps.conductor.template_executor import load_payload_variants
            from apps.conductor.constants import CONCEPT_ENGINE_MAP
            # Pass 1: read concept_id stored in artifact (GenericHTTPEngine / OracleSearchEngine)
            _art_raw = terminal.artifact or {}
            _art_dict = _art_raw if isinstance(_art_raw, dict) else {}
            if not _art_dict and isinstance(_art_raw, str):
                try: _art_dict = _json_local.loads(_art_raw)
                except Exception: pass
            # artifact is stored as the full payload dict ({"artifact": {...}}) for succeeded
            _inner = _art_dict.get("artifact", _art_dict) if isinstance(_art_dict, dict) else {}
            _cid = (_inner.get("concept_id", "") if isinstance(_inner, dict) else "") or ""
            # Pass 2: reverse lookup if artifact had no concept_id
            if not _cid:
                engine_to_concept = {v: k for k, v in CONCEPT_ENGINE_MAP.items() if v}
                _cid = engine_to_concept.get(terminal.engine_id, "")
            if _cid:
                payload_variants = load_payload_variants(_cid)
                concept_id_for_variants = _cid
        except Exception:
            pass

    response = templates.TemplateResponse(
        request,
        "partials/_result_zone.html",
        {
            "parsed":            parsed,
            "finding_id":        finding_id,
            "investigation_id":  investigation_id,
            "next_options":      next_options,
            "model_advice":      model_advice,
            "payload_variants":  payload_variants,   # Phase E
            "concept_id":        concept_id_for_variants,  # Phase E
        },
    )
    # When session is captured, tell the frontend to refresh the selection card
    # so js_spider's requires_session badge updates
    extra_headers: dict = {}
    if parsed.session_captured:
        extra_headers["HX-Trigger"] = "session-captured"
    response.headers.update(extra_headers)
    return response


# ── Phase E Part 1 — payload variant execution ───────────────────────────────


@router.post(
    "/investigations/{investigation_id}/execute-variant",
    response_class=HTMLResponse,
)
async def execute_variant(
    investigation_id: str,
    request: Request,
):
    """Execute a selected payload variant from Layer 3 zone.

    Body (form): engine_id, concept_id, finding_id, variant_index
    Response: new _result_zone.html partial with updated result.
    C6 preserved: operator selected variant and clicked Execute Next Step.
    """
    form = await request.form()
    engine_id     = str(form.get("engine_id", "")).strip()
    concept_id    = str(form.get("concept_id", "")).strip()
    finding_id    = str(form.get("finding_id", "")).strip()
    try:
        variant_index = int(str(form.get("variant_index", "0")))
    except (ValueError, TypeError):
        variant_index = 0

    if not engine_id or not finding_id:
        return HTMLResponse(
            content='<div class="text-red-400 text-xs py-2">Invalid variant request.</div>'
        )

    from apps.conductor.template_executor import load_payload_variants, load_template, render_payload
    from apps.conductor.result_parser import ParsedResult

    variants = load_payload_variants(concept_id) if concept_id else []
    variant  = variants[variant_index] if 0 <= variant_index < len(variants) else None

    _hint = variant.get("payload_hint", "").strip().lower() if variant else ""
    _is_extraction        = _hint == "mode: extract"
    _is_enumeration       = _hint == "mode: enumerate"
    _is_keys_enumerate    = _hint == "mode: keys_enumerate"
    _is_where_extract     = _hint == "mode: where_extract"

    try:
        from apps.conductor.shared import get_shared_conductor
        _conductor = get_shared_conductor()
        _ctx = _conductor.get_context(investigation_id)
        if _ctx:
            if _is_extraction or _is_enumeration or _is_keys_enumerate or _is_where_extract:
                # Route to OracleSearchEngine with the appropriate strategy
                _dispatch_engine_id = "oracle_search"
                if _is_extraction:
                    _strategy = "binary_search"
                elif _is_enumeration:
                    _strategy = "dictionary_scan"
                elif _is_keys_enumerate:
                    _strategy = "keys_enumeration"
                elif _is_where_extract:
                    _strategy = "where_extract"
                else:
                    _strategy = "binary_search"
                # Resolve target_account from investigation objective for parameterization
                _target_account = ""
                try:
                    from apps.conductor.investigation_state import load_state_async
                    from apps.conductor.template_executor import extract_target_account as _eta
                    _state = await load_state_async(investigation_id)
                    _target_account = _eta(_state.objective or "") or ""
                except Exception:
                    pass
                extra = {
                    "concept_id":     concept_id,
                    "correlation_id": finding_id,
                    "strategy":       _strategy,
                    "target_account": _target_account,
                }
            else:
                _dispatch_engine_id = engine_id
                extra = {}
                if variant:
                    extra["variant_title"]   = variant.get("title", "")
                    extra["variant_payload"] = variant.get("payload_hint", "")
            await _ctx.exec_orch.dispatch_engine(
                _dispatch_engine_id,
                correlation_id=finding_id,
                extra_config=extra or None,
            )
            # Return running zone for the same finding
            _poll_url = (
                f"/api/v1/validation/workspace/investigations/{investigation_id}"
                f"/result-zone/{finding_id}"
            )
            if _is_extraction:
                _variant_label = "Extracting field value"
            elif _is_enumeration:
                _variant_label = "Enumerating unknown fields"
            elif _is_keys_enumerate:
                _variant_label = "Enumerating fields via $where Object.keys"
            elif _is_where_extract:
                _variant_label = "Extracting token value via $where"
            else:
                _variant_label = f"Running variant: {variant['title']}" if variant else engine_id
            content = (
                f'<div id="result-zone-{finding_id}" style="min-height:48px;" '
                f'class="rounded-md border border-dashed border-[#d0d7de] '
                f'px-2 py-1.5 text-[10px] text-zinc-400" '
                f'hx-get="{_poll_url}" hx-trigger="every 3s" hx-swap="outerHTML">'
                f'<span style="animation:invSuggestedPulse 1.2s ease-in-out infinite;'
                f'display:inline-block;">&#x25B8;</span> '
                f'{_variant_label}…'
                f'</div>'
            )
            return HTMLResponse(
                content=content,
                headers={"HX-Trigger": "reload-branches"},
            )
    except Exception as exc:
        _routes_logging.getLogger("routes.execute_variant").warning(
            "execute_variant failed: %s", exc
        )

    # Fallback: no active context
    return HTMLResponse(
        content=f'<div class="text-amber-700 text-xs py-2">'
                f'No active investigation context — start an investigation first.'
                f'</div>'
    )


# ── Phase 43 — runtime pseudo-node context panel ───────────────────────


async def _runtime_context_panel(
    investigation_id: str, node_id: str, request: Request,
) -> HTMLResponse:
    """Render the reasoning context for a bootstrap- or execution-stage node.

    Pseudo-node ids:
      boot-{run_id}-s{i}     — bootstrap reasoning stage
      exec-{run_id}-s{i}     — execution stage
      exec-{run_id}-r{j}     — execution result

    The node lives only in the runtime store (in-memory). The assembler
    knows nothing about it, so we resolve it directly from bootstrap /
    execution runtime modules and shape a small dict for the panel.
    """
    from apps.investigation_workspace.bootstrap.runtime import (
        get_run as get_bootstrap_run,
    )
    from apps.investigation_workspace.execution.runtime import (
        active_runs as exec_active_runs,
    )

    panel_ctx: dict = {
        "request":          request,
        "investigation_id": investigation_id,
        "node_id":          node_id,
        "title":            "",
        "subtitle":         "",
        "status":           "completed",
        "actions":          [],
        "tools":            [],
        "detected":         [],
        "confidence":       "",
        "spawned":          [],
        "kind":             "",
    }

    # ── Bootstrap stage ────────────────────────────────────────────────
    if node_id.startswith("boot-"):
        # Format: boot-{phase_run_id}-s{i}
        rest = node_id[len("boot-"):]
        try:
            run_id, sid = rest.rsplit("-", 1)
            idx = int(sid[1:])
        except (ValueError, IndexError):
            run_id, idx = None, -1
        phased_run = get_bootstrap_run(investigation_id)
        # Search for the matching PhaseRun across all three phases
        phase_run = None
        if phased_run is not None:
            for _pr in (
                phased_run.recon_run,
                phased_run.enumeration_run,
                phased_run.exploitation_run,
            ):
                if _pr is not None and _pr.run_id == run_id:
                    phase_run = _pr
                    break
        if phase_run is None or idx < 0 or idx >= len(phase_run.stages):
            panel_ctx["title"]    = "Bootstrap stage"
            panel_ctx["subtitle"] = "no longer in runtime memory"
        else:
            stage = phase_run.stages[idx]
            panel_ctx.update({
                "title":      stage.label,
                "subtitle":   f"{phase_run.phase} phase",
                "status":     "completed" if stage.completed_at else "running",
                "actions":    list(stage.actions),
                "tools":      list(stage.tools),
                "detected":   list(stage.detected),
                "confidence": stage.confidence or "—",
                "spawned":    list(stage.spawned),
                "kind":       "bootstrap_stage",
            })

    # ── Execution stage or result ─────────────────────────────────────
    elif node_id.startswith("exec-"):
        # Format: exec-{run_id}-s{i} or exec-{run_id}-r{j}
        rest = node_id[len("exec-"):]
        try:
            run_id, tag = rest.rsplit("-", 1)
            kind_letter = tag[:1]
            idx = int(tag[1:])
        except (ValueError, IndexError):
            run_id, kind_letter, idx = None, "", -1
        run = next((r for r in exec_active_runs(investigation_id)
                    if r.run_id == run_id), None)
        if run is None or idx < 0:
            panel_ctx["title"]    = "Execution step"
            panel_ctx["subtitle"] = "no longer in runtime memory"
        elif kind_letter == "s" and idx < len(run.stages):
            stg = run.stages[idx]
            panel_ctx.update({
                "title":      stg.label,
                "subtitle":   "execution stage",
                "status":     "completed" if stg.completed_at else "running",
                # Phase 49 — real probes carry reasoning metadata; surface it
                # just like bootstrap stages do.
                "actions":    list(getattr(stg, "actions", ())),
                "tools":      list(getattr(stg, "tools", ())),
                "detected":   list(getattr(stg, "detected", ())),
                "confidence": getattr(stg, "confidence", "—"),
                "kind":       "execution_stage",
            })
        elif kind_letter == "r" and idx < len(run.results):
            res = run.results[idx]
            payload = getattr(res, "payload", None)
            # Phase 54 — if the probe emitted a structured payload, render
            # the rich evidence panel. Otherwise fall back to the legacy
            # flattened-evidence panel and tag it 'Legacy evidence' so the
            # operator sees the schema gap.
            if payload:
                return await _structured_evidence_panel(
                    investigation_id, node_id, run, res, request,
                )
            evidence_lines = _format_evidence_lines(getattr(res, "evidence", {}))
            panel_ctx.update({
                "title":    res.label,
                "subtitle": "execution result · legacy evidence",
                "status":   {"blocked":  "completed",
                             "persists": "failed",
                             "detected": "discovered",
                             "note":     "completed"}.get(res.kind, "completed"),
                "detected": evidence_lines or [res.label],
                "kind":     "execution_result",
            })
        else:
            panel_ctx["title"]    = "Execution step"
            panel_ctx["subtitle"] = "step index out of range"

    return templates.TemplateResponse(
        "partials/context_panel_runtime.html",
        panel_ctx,
    )


async def _capture_bundle_panel(
    investigation_id: str, node_id: str, request: Request,
) -> HTMLResponse:
    """Phase 58 — render the capture-bundle file browser side panel.

    Node-id shape: bundle-{bundle_id}. Look up the bundle in the
    in-memory registry and render the file tree.
    """
    from apps.investigation_workspace.capture import get_bundle

    bundle_id = node_id[len("bundle-"):]
    bundle = get_bundle(bundle_id)
    if bundle is None:
        # Phase 57d — bundle expired (process restart cleared
        # _BUNDLES). Show a specific panel that tells the operator
        # what happened and how to recover, rather than the generic
        # "no longer in runtime memory" fallback. Persistence is a
        # separate concern (out of scope for this PR).
        return templates.TemplateResponse(
            "partials/capture_bundle_expired.html",
            {
                "request":          request,
                "investigation_id": investigation_id,
                "node_id":          node_id,
                "bundle_id":        bundle_id,
            },
        )
    # Phase 57c — Promote HOW_TO_REPRODUCE.md to the top of the
    # artifact list and pre-render its markdown server-side so the
    # template can show it auto-expanded as rich HTML. Backward-
    # compatible: bundles without one render as before.
    readme_idx   = next((i for i, a in enumerate(bundle.artifacts)
                         if a.filename == "HOW_TO_REPRODUCE.md"), None)
    readme_html  = None
    if readme_idx is not None:
        readme_html = _render_markdown_minimal(
            bundle.artifacts[readme_idx].content,
        )
    other_artifacts = [
        a for i, a in enumerate(bundle.artifacts) if i != readme_idx
    ]
    return templates.TemplateResponse(
        "partials/capture_bundle.html",
        {
            "request":          request,
            "investigation_id": investigation_id,
            "node_id":          node_id,
            "bundle":           bundle,
            "readme_artifact":  (bundle.artifacts[readme_idx]
                                  if readme_idx is not None else None),
            "readme_html":      readme_html,
            "other_artifacts":  other_artifacts,
        },
    )


# Phase 57c — minimal inline markdown renderer.
# Supports the 6 features the reproduction template uses:
#   - h1 / h2 / h3 headings
#   - ```fenced code blocks```
#   - `inline code`
#   - **bold**
#   - bullet lists (- or *)
#   - paragraphs
# Deliberately NOT a full markdown library — we ship reproduction
# guides authored in-repo, not arbitrary user input, so the surface
# stays small. If a future probe needs tables or links, expand here.

_MD_FENCE_RE = re.compile(r"^```(\w*)\s*$")
_MD_BULLET_RE = re.compile(r"^[-*]\s+(.*)$")


def _render_markdown_minimal(md: str) -> str:
    import html

    def inline(s: str) -> str:
        s = html.escape(s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"`([^`]+)`",
                   r'<code class="px-1 py-0.5 rounded bg-zinc-800 '
                   r'text-zinc-200">\1</code>', s)
        # Bare URLs (http/https) → clickable, target=_blank
        s = re.sub(
            r"(?<!\")(https?://[^\s<]+[^\s.,<])",
            r'<a href="\1" target="_blank" rel="noopener noreferrer" '
            r'class="text-blue-400 hover:text-blue-300 underline">\1</a>',
            s,
        )
        return s

    out:        list[str] = []
    in_code:    bool = False
    code_buf:   list[str] = []
    in_list:    bool = False
    code_idx:   int = 0

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    for raw_line in md.split("\n"):
        line = raw_line.rstrip("\r")
        m_fence = _MD_FENCE_RE.match(line)
        if m_fence:
            if in_code:
                close_list()
                code_text = "\n".join(code_buf)
                code_escaped = html.escape(code_text)
                code_idx += 1
                # Each code block gets its own Copy button (same JS
                # pattern as the regular file panel's Copy).
                out.append(
                    f'<div class="my-2 relative group">'
                    f'<button type="button" '
                    f'class="absolute top-1 right-1 text-[10px] text-zinc-400 '
                    f'hover:text-zinc-200 px-1.5 py-0.5 border border-zinc-700 '
                    f'rounded bg-zinc-900/80" '
                    f'data-md-code="{code_idx}" '
                    f'onclick="const t=this.nextElementSibling.querySelector(\'code\').textContent;'
                    f'navigator.clipboard.writeText(t);'
                    f"this.textContent='Copied';"
                    f'setTimeout(()=>this.textContent=\'Copy\',1500);">Copy</button>'
                    f'<pre class="font-mono text-[10px] text-zinc-200 '
                    f'bg-[#0d1117] border border-zinc-800 rounded p-2 '
                    f'overflow-x-auto whitespace-pre"><code>{code_escaped}</code></pre>'
                    f'</div>'
                )
                code_buf = []
                in_code = False
            else:
                close_list()
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue
        if line.startswith("### "):
            close_list()
            out.append(
                f'<h3 class="text-zinc-100 font-semibold mt-3 mb-1 text-[12px]">'
                f'{inline(line[4:])}</h3>'
            )
        elif line.startswith("## "):
            close_list()
            out.append(
                f'<h2 class="text-zinc-100 font-semibold mt-4 mb-1 text-[13px] '
                f'border-b border-zinc-800 pb-0.5">'
                f'{inline(line[3:])}</h2>'
            )
        elif line.startswith("# "):
            close_list()
            out.append(
                f'<h1 class="text-zinc-100 font-semibold mt-2 mb-2 text-sm">'
                f'{inline(line[2:])}</h1>'
            )
        elif _MD_BULLET_RE.match(line):
            if not in_list:
                out.append('<ul class="list-disc list-inside space-y-1 my-1 '
                           'text-[11px] text-zinc-300">')
                in_list = True
            item = _MD_BULLET_RE.match(line).group(1)
            out.append(f'<li>{inline(item)}</li>')
        elif line.strip() == "":
            close_list()
        else:
            close_list()
            out.append(
                f'<p class="text-[11px] text-zinc-300 leading-relaxed my-1">'
                f'{inline(line)}</p>'
            )

    close_list()
    if in_code:   # unterminated fence — emit what we have
        leftover = html.escape("\n".join(code_buf))
        out.append(f'<pre class="font-mono text-[10px]">{leftover}</pre>')
    return "\n".join(out)


@router.get("/bundles/{bundle_id}")
async def get_bundle_metadata(bundle_id: str):
    """Phase 58 — return bundle metadata (no artifact contents)."""
    from apps.investigation_workspace.capture import get_bundle
    b = get_bundle(bundle_id)
    if b is None:
        raise HTTPException(status_code=404, detail="Bundle not found")
    return {
        "bundle_id":       b.bundle_id,
        "investigation_id": b.investigation_id,
        "finding_id":      b.finding_id,
        "action_id":       b.action_id,
        "exploit_path_id": b.exploit_path_id,
        "created_at":      b.created_at,
        "label":           b.label,
        "artifacts": [
            {
                "filename":     a.filename,
                "content_type": a.content_type,
                "size_bytes":   a.size_bytes,
                "description":  a.description,
            }
            for a in b.artifacts
        ],
    }


@router.get("/bundles/{bundle_id}/files/{filename}", response_class=HTMLResponse)
async def get_bundle_file(bundle_id: str, filename: str):
    """Phase 58 — return one artifact's content with its declared Content-Type."""
    from fastapi.responses import Response as _Response

    from apps.investigation_workspace.capture import get_bundle
    b = get_bundle(bundle_id)
    if b is None:
        raise HTTPException(status_code=404, detail="Bundle not found")
    for a in b.artifacts:
        if a.filename == filename:
            return _Response(content=a.content, media_type=a.content_type)
    raise HTTPException(status_code=404, detail=f"Artifact '{filename}' not found in bundle")


async def _exploitation_path_panel(
    investigation_id: str, node_id: str, request: Request,
) -> HTMLResponse:
    """Render the context panel for an exploitation_path pseudo-node.

    Node-id shape: path-{finding_node_id}-{path_id}
    Resolution: split off the path_id (last dotted-segment suffix from
    the end), look up the registry, render label + description +
    family + suggested-actions placeholder. Future work attaches real
    suggested actions per path here.
    """
    from apps.investigation_workspace.exploitation_paths import (
        get_path,
        presentation_for,
    )

    # path-{finding_node_id}-{path_id} → strip "path-" then split off the
    # last hyphen-separated segment that contains a "." (dotted path id).
    rest = node_id[len("path-"):]
    # path_id is a dotted string; find the trailing one. The finding
    # node_id is "disc-{uuid}" (no dots). So locate the LAST "-" before
    # a "." segment.
    # Simplest: try increasingly long suffixes for a known path id.
    from apps.investigation_workspace.exploitation_paths.taxonomy import _PATHS
    path_id  = ""
    finding_node_id = ""
    for known in sorted(_PATHS.keys(), key=len, reverse=True):
        suffix = "-" + known
        if rest.endswith(suffix):
            path_id  = known
            finding_node_id = rest[:-len(suffix)]
            break
    p = get_path(path_id) if path_id else None
    if p is None:
        panel_ctx = {
            "request":          request,
            "investigation_id": investigation_id,
            "node_id":          node_id,
            "title":            "Exploitation path",
            "subtitle":         "unknown path id",
            "status":           "completed",
            "actions":          [],
            "tools":            [],
            "detected":         [],
            "confidence":       "",
            "spawned":          [],
            "kind":             "exploitation_path",
        }
        return templates.TemplateResponse(
            "partials/context_panel_runtime.html", panel_ctx,
        )

    pres = presentation_for(path_id)
    detected_lines: list[str] = [
        f"path_id: {path_id}",
        f"family:  {pres.family}",
    ]
    if p.parent_id:
        detected_lines.append(f"parent:  {p.parent_id}")
    detected_lines.append(f"anchored on: {finding_node_id}")

    panel_ctx = {
        "request":          request,
        "investigation_id": investigation_id,
        "node_id":          node_id,
        "title":            p.label,
        "subtitle":         "exploitation path",
        "status":           "ready",
        "actions":          [p.description],
        "tools":            [],
        "detected":         detected_lines,
        "confidence":       "",
        "spawned":          [],
        "kind":             "exploitation_path",
    }
    return templates.TemplateResponse(
        "partials/context_panel_runtime.html", panel_ctx,
    )


async def _structured_evidence_panel(
    investigation_id: str, node_id: str, run, result, request: Request,
) -> HTMLResponse:
    """Render the Phase 54 structured-evidence panel.

    Inputs:
      run    — ExecutionRun (carries action_id we use for path attribution)
      result — ResultState (carries the structured payload)

    The renderer skips absent payload sub-fields gracefully. next_actions
    are resolved through the catalog/probe precedence rule and rendered
    as Execute buttons that POST to the same endpoint as the ghost-node
    click — single convergence path.
    """
    from apps.investigation_workspace.exploitation_paths.next_actions import (
        NEXT_ACTIONS_BY_PATH,
        resolve_next_actions,
    )

    # Attribute action_kind → exploit_path_id so we can resolve catalog
    # next_actions for the panel even if the probe didn't enrich.
    kind_to_path = {
        s.action_kind: pid
        for pid, specs in NEXT_ACTIONS_BY_PATH.items()
        for s in specs
    }
    ak = (run.action_id or "")
    if ak.startswith("suggestion:"):
        ak = ak[len("suggestion:"):]
    # Phase 54b — primary: run.exploit_path_id (authoritative, set when
    # the operator clicked Execute). Fallback: legacy reverse-lookup for
    # in-flight runs that started before 54b shipped.
    path_id = getattr(run, "exploit_path_id", None) or kind_to_path.get(ak, "")

    # Finding id, for the Execute POST URL.
    finding_id = run.parent_node_id or ""
    if finding_id.startswith("disc-"):
        finding_id = finding_id[len("disc-"):]

    from apps.investigation_workspace.execution.runtime import has_been_executed

    next_acts = resolve_next_actions(result.payload, path_id)
    next_actions_view = [
        {
            "id":          na.action_kind,
            "action_kind": na.action_kind,
            "label":       na.label,
            "reason":      na.reason,
            "source":      (
                "probe" if (result.payload or {}).get("next_actions") else "catalog"
            ),
            "executed":    has_been_executed(investigation_id, finding_id, na.action_kind),
            "inputs":      [
                {"name": inp.name, "location": inp.location, "placeholder": inp.placeholder}
                for inp in na.inputs
            ],
        }
        for na in next_acts
    ]

    payload = result.payload or {}
    return templates.TemplateResponse(
        "partials/structured_evidence.html",
        {
            "request":            request,
            "investigation_id":   investigation_id,
            "node_id":            node_id,
            "label":              result.label,
            "kind":               result.kind,        # detected/blocked/persists/note
            "status":             {"blocked":  "completed",
                                   "persists": "failed",
                                   "detected": "discovered",
                                   "note":     "completed"}.get(result.kind, "completed"),
            "request_obj":        payload.get("request"),
            "response_obj":       payload.get("response"),
            "sent":               payload.get("sent"),
            "observed":           payload.get("observed"),
            "analysis":           payload.get("analysis") or {},
            "next_actions":       next_actions_view,
            "finding_id":         finding_id,
            "exploit_path_id":    path_id,
            "action_kind":        ak,
            # run.run_id is passed as parent_run_id so mutate card Execute
            # URLs can anchor the mutate run under this result node in the
            # mind map (Fix 1 — mind map hierarchy).
            "parent_run_id":      run.run_id,
        },
    )


def _format_evidence_lines(evidence: dict) -> list[str]:
    """Render a probe's evidence dict as compact reviewable lines.

    Phase 49 — keeps the operator-facing panel readable: skips internal
    keys, truncates long values, expands short lists. Lists of structured
    items (third_party_examples, first_20) are shown as small enumerated
    blocks so a path the probe actually fetched is visible at a glance.
    """
    if not evidence:
        return []
    lines: list[str] = []
    for key, val in evidence.items():
        if val is None or val == "" or val == [] or val == {}:
            continue
        if isinstance(val, str):
            shown = val if len(val) <= 120 else val[:120] + "…"
            lines.append(f"{key}: {shown}")
        elif isinstance(val, (int, float, bool)):
            lines.append(f"{key}: {val}")
        elif isinstance(val, list):
            if len(val) <= 5:
                lines.append(f"{key}: {val}")
            else:
                lines.append(f"{key} ({len(val)}): {val[:5]} …")
        elif isinstance(val, dict):
            sub_keys = list(val)[:5]
            extra = "" if len(val) <= 5 else f" (+{len(val) - 5} more)"
            lines.append(f"{key}: {sub_keys}{extra}")
        else:
            lines.append(f"{key}: {val!r}")
    return lines[:12]


# ── Branch action inline card (Phase 20 — approve / complete / verify) ──


def _compute_next_hint(action, approval) -> str:
    """Phase 32 — operator-readable "what happens next" sentence.

    Order of preference:
      1. unlock_rules narrative when the action has a defined progression
      2. action.remediation_context (defensive actions carry this)
      3. state-based default sentence
    """
    from apps.investigation_core.guided_actions.models.approval import ApprovalStatus
    from apps.investigation_workspace.feed.unlock_rules import (
        unlocks_for_action_completed,
    )

    status = approval.status if approval else None
    is_defensive = bool(getattr(action, "is_defensive", False))

    # Pull from unlock_rules — only meaningful for actions that have one
    rule = unlocks_for_action_completed(action.action_id) or {}
    rule_narrative = str(rule.get("narrative", "") or "")

    if status == ApprovalStatus.COMPLETED:
        if is_defensive:
            return (
                "Capture a post-remediation snapshot to lock the verified "
                "state, or mark a regression if the weakness returns."
            )
        if rule_narrative:
            return rule_narrative
        return "Step is complete. Move to the next branch in the corridor."

    if status == ApprovalStatus.APPROVED:
        if is_defensive:
            return (
                "Capture verification evidence, then mark complete to advance "
                "the verification status on this remediation branch."
            )
        if rule_narrative:
            return (
                "Capture evidence and mark complete — "
                + rule_narrative.lower().rstrip(".") + "."
            )
        return "Capture evidence, then mark complete to advance the branch."

    # Not approved (pending / rejected / none)
    if is_defensive:
        return (
            "Approving reveals verification steps. Evidence capture stays "
            "inline on this card."
        )
    return "Approving reveals step-by-step guidance and unlocks evidence capture."


# Phase 59b — branch_action_approve + _resolve_action_parent_node_id
# removed alongside the canned-script execution mechanism. The route
# drove the canned-script "Approve to execute" deception: clicking
# Approve fired a kick_off(script=...) that ran fake-animation stages
# and produced a "Capability executed" outcome with no real work.
# After Phase 59b, every operator-clickable execution goes through
# /finding/{fid}/suggest/{ak}/execute and runs a real probe via
# _runner_from_probe.


@router.post(
    "/investigations/{investigation_id}/branch-action/{action_id}/complete",
    response_class=HTMLResponse,
)
async def branch_action_complete(
    investigation_id: str, action_id: str, request: Request,
):
    """Mark an action complete from the branch view; returns refreshed card."""
    from apps.investigation_core.guided_actions.approvals.approval_service import (
        ApprovalService,
    )
    from apps.investigation_core.guided_actions.registry.action_registry import (
        action_registry,
    )

    if action_registry.get(action_id) is None:
        raise HTTPException(status_code=404, detail="Action not found")
    async with get_db() as db:
        await ApprovalService(db).complete(
            investigation_id, action_id, evidence_ids=[],
        )
    return HTMLResponse(content="", status_code=200, headers={"HX-Trigger": "reload-branches"})


# ── Phase 21 — verification snapshot + regression endpoints ───────────────


@router.post(
    "/investigations/{investigation_id}/branch-action/{action_id}/capture-snapshot",
    response_class=HTMLResponse,
)
async def branch_action_capture_snapshot(
    investigation_id: str, action_id: str, request: Request, kind: str = "post_remediation",
):
    """Capture a post-remediation posture snapshot anchored to this verification action.

    The snapshot is investigation-scoped (PostureSnapshotService.capture takes no
    action_id). The action_id is recorded on the label so the operator can
    later associate snapshots with the verification action that triggered
    them.
    """
    from apps.investigation_core.defensive.models.posture import PostureSnapshotKind
    from apps.investigation_core.defensive.services.posture_service import (
        PostureSnapshotService,
    )
    from apps.investigation_core.guided_actions.registry.action_registry import (
        action_registry,
    )

    action = action_registry.get(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Action not found")
    try:
        snap_kind = PostureSnapshotKind(kind)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid kind: {kind}") from e

    async with get_db() as db:
        await PostureSnapshotService(db).capture(
            investigation_id,
            label=f"Verification: {action.title}",
            snapshot_kind=snap_kind,
            notes=f"Triggered from inline verification card for action_id={action_id}",
            captured_by="branch-workspace",
        )
    return HTMLResponse(content="", status_code=200, headers={"HX-Trigger": "reload-branches"})


@router.post(
    "/investigations/{investigation_id}/branch-action/{action_id}/mark-regression",
    response_class=HTMLResponse,
)
async def branch_action_mark_regression(
    investigation_id: str, action_id: str, request: Request,
):
    """Capture a regression_check snapshot for this verification action.

    The branch assembler compares the latest post_remediation snapshot
    against subsequent snapshots and surfaces a REGRESSION state on any
    REMEDIATION node whose cluster appears in the regressed bucket.
    """
    from apps.investigation_core.defensive.models.posture import PostureSnapshotKind
    from apps.investigation_core.defensive.services.posture_service import (
        PostureSnapshotService,
    )
    from apps.investigation_core.guided_actions.registry.action_registry import (
        action_registry,
    )

    action = action_registry.get(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Action not found")
    async with get_db() as db:
        await PostureSnapshotService(db).capture(
            investigation_id,
            label=f"Regression check: {action.title}",
            snapshot_kind=PostureSnapshotKind.REGRESSION_CHECK,
            notes=(
                "Regression-check snapshot. Operator flagged this defensive "
                f"action_id={action_id} as showing regression — assembler will "
                "compare against the latest post_remediation snapshot."
            ),
            captured_by="branch-workspace",
        )
    return HTMLResponse(content="", status_code=200, headers={"HX-Trigger": "reload-branches"})


# ── Inline evidence capture — pre-populated from finding/action context ──


@router.get(
    "/investigations/{investigation_id}/evidence/capture/form",
    response_class=HTMLResponse,
)
async def evidence_capture_form(
    investigation_id: str,
    request: Request,
    finding_id: str | None = None,
    action_id: str | None = None,
    objective_key: str | None = None,
):
    """Return a prefilled inline evidence capture form.

    Pre-populates from the finding interpretation:
      - title hint (e.g. "Authenticated response — SQLi auth bypass")
      - expected artifact type (e.g. http_response, payload_attempt)
      - evidence goals (rendered as hints alongside the form)
      - related learning concepts
      - linked finding_id / guided_action_id / objective_key

    Returned HTML is HTMX-swapped in place where the user clicked
    "Capture evidence" — no tab switch required.
    """
    from apps.investigation_core.evidence.models.artifact import (
        ARTIFACT_TYPE_LABELS,
        ArtifactType,
    )
    from apps.investigation_core.guided_actions.registry.action_registry import (
        action_registry,
    )
    from apps.investigation_core.services.investigation_service import (
        InvestigationService,
    )
    from apps.investigation_workspace.feed.interpretations import interpret
    from apps.scanner_orchestration.storage.finding_repo import (
        NormalizedFindingRepository,
    )

    finding = None
    interp: dict = {}
    finding_type = None
    async with get_db() as db:
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if finding_id:
            f_repo = NormalizedFindingRepository(db)
            finding = await f_repo.get_by_id(finding_id)
            if finding:
                finding_type = finding.finding_type
                interp = interpret(finding_type)

    action = action_registry.get(action_id) if action_id else None

    # Suggest a default artifact type based on action / finding family
    default_type = ArtifactType.NOTE
    if action:
        a_steps_evidence = (action.expected_evidence or "").lower()
        if "screenshot" in a_steps_evidence:
            default_type = ArtifactType.SCREENSHOT
        elif "http request" in a_steps_evidence:
            default_type = ArtifactType.HTTP_REQUEST
        elif "http response" in a_steps_evidence or "response body" in a_steps_evidence:
            default_type = ArtifactType.HTTP_RESPONSE
        elif "payload" in a_steps_evidence:
            default_type = ArtifactType.PAYLOAD_ATTEMPT
        elif "credential" in a_steps_evidence:
            default_type = ArtifactType.EXTRACTED_CREDENTIAL

    # Pre-build a sensible title prefix
    title_prefix = ""
    if action:
        title_prefix = action.title
    elif finding:
        title_prefix = (interp.get("headline") or "Finding") if interp else "Finding"

    # Find the matched objective text if a key was provided
    objective_text = None
    if objective_key and interp:
        obj_keys = list(interp.get("ctf_objective_keys") or [])  # type: ignore[arg-type]
        objs = list(interp.get("ctf_objectives") or [])  # type: ignore[arg-type]
        for k, t in zip(obj_keys, objs, strict=False):
            if k == objective_key:
                objective_text = t
                break

    return templates.TemplateResponse(
        "partials/evidence_capture_form.html",
        {
            "request": request,
            "investigation_id": investigation_id,
            "finding": finding,
            "finding_id": finding_id,
            "finding_type": finding_type,
            "action": action,
            "action_id": action_id,
            "objective_key": objective_key,
            "objective_text": objective_text,
            "evidence_goals": list(interp.get("evidence_goals") or []) if interp else [],
            "learning_concepts": list(interp.get("learning_concepts") or []) if interp else [],
            "default_type": str(default_type),
            "artifact_types": [t for t in ArtifactType],
            "artifact_type_labels": ARTIFACT_TYPE_LABELS,
            "title_prefix": title_prefix,
        },
    )


@router.post(
    "/investigations/{investigation_id}/evidence/capture",
    response_class=HTMLResponse,
)
async def evidence_capture_submit(
    investigation_id: str,
    request: Request,
    artifact_type: str = Form("auto"),
    title: str = Form(""),
    content: str = Form(""),
    description: str = Form(""),
    finding_id: str = Form(""),
    action_id: str = Form(""),
    objective_key: str = Form(""),
):
    """Capture evidence inline, with strong linkage to finding + action + objective.

    Phase 28: quick-capture friendly. If `artifact_type` is "auto" or empty,
    infer from the content (deterministic heuristic, no LLM). If `title` is
    empty, derive from the first non-empty line of content (truncated).
    """
    from apps.investigation_core.evidence.models.artifact import ArtifactType
    from apps.investigation_core.evidence.services.evidence_service import (
        EvidenceService,
    )
    from apps.investigation_core.evidence.validation.rules import (
        ArtifactValidationError,
    )
    from apps.investigation_core.guided_actions.approvals.approval_service import (
        ApprovalService,
    )
    from apps.investigation_core.guided_actions.models.approval import ApprovalStatus

    # Phase 28: lenient type resolution.
    if (not artifact_type) or artifact_type.lower() == "auto":
        a_type = infer_artifact_type(content)
    else:
        try:
            a_type = ArtifactType(artifact_type)
        except ValueError as e:
            raise HTTPException(
                status_code=400, detail=f"Invalid artifact_type: {artifact_type}"
            ) from e

    # Phase 28: derive title from first non-empty line if absent.
    if not title.strip():
        title = _derive_title_from_content(content) or "Quick capture"

    tags: list[str] = []
    if finding_id:
        tags.append("finding")
    if action_id:
        tags.append("action")
    if objective_key:
        tags.append("objective")

    async with get_db() as db:
        svc = EvidenceService(db)
        try:
            artifact = await svc.capture(
                investigation_id,
                a_type,
                title.strip() or "Evidence",
                content,
                description=description,
                finding_id=finding_id or None,
                guided_action_id=action_id or None,
                tags=tags,
                metadata={"objective_key": objective_key} if objective_key else None,
            )
        except ArtifactValidationError as e:
            return HTMLResponse(
                content=(
                    f'<div class="capture-error">Evidence rejected: '
                    f'{str(e)}</div>'
                ),
                status_code=422,
            )

        # If we captured for an approved action, mark completion now —
        # explicit user activity closes the lifecycle loop.
        if action_id:
            approval_svc = ApprovalService(db)
            approval = await approval_svc.get_approval(investigation_id, action_id)
            if approval and approval.status == ApprovalStatus.APPROVED:
                try:
                    await approval_svc.complete(
                        investigation_id,
                        action_id,
                        evidence_ids=[artifact.evidence_id, *approval.evidence_refs],
                    )
                except ValueError:
                    pass

    return templates.TemplateResponse(
        "partials/evidence_capture_success.html",
        {
            "request": request,
            "investigation_id": investigation_id,
            "artifact": artifact,
            "finding_id": finding_id,
            "action_id": action_id,
            "objective_key": objective_key,
        },
    )


# ── Posture snapshots + comparison (Phase 17) ─────────────────────────────


class CaptureSnapshotRequest(BaseModel):
    label: str = ""
    snapshot_kind: str = "baseline"
    campaign_id: str | None = None
    notes: str | None = None


@router.post(
    "/investigations/{investigation_id}/posture-snapshots",
    response_class=HTMLResponse,
)
async def capture_posture_snapshot(
    investigation_id: str,
    request: Request,
    label: str = Form(""),
    snapshot_kind: str = Form("baseline"),
    notes: str = Form(""),
):
    from apps.investigation_core.defensive.models.posture import PostureSnapshotKind
    from apps.investigation_core.defensive.services.posture_service import (
        PostureSnapshotService,
    )
    from apps.investigation_core.services.investigation_service import (
        InvestigationService,
    )

    try:
        kind = PostureSnapshotKind(snapshot_kind)
    except ValueError as e:
        raise HTTPException(
            status_code=400, detail=f"Invalid snapshot_kind: {snapshot_kind}"
        ) from e

    async with get_db() as db:
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        svc = PostureSnapshotService(db)
        snapshot = await svc.capture(
            investigation_id,
            label=label,
            snapshot_kind=kind,
            notes=notes or None,
        )

    return templates.TemplateResponse(
        "partials/posture_snapshot_chip.html",
        {"request": request, "snapshot": snapshot},
    )


@router.get(
    "/investigations/{investigation_id}/posture-snapshots/partial",
    response_class=HTMLResponse,
)
async def posture_snapshots_partial(investigation_id: str, request: Request):
    from apps.investigation_core.defensive.models.posture import POSTURE_KIND_LABELS
    from apps.investigation_core.defensive.services.posture_service import (
        PostureSnapshotService,
    )

    async with get_db() as db:
        svc = PostureSnapshotService(db)
        snapshots = await svc.list_for_investigation(investigation_id)

    return templates.TemplateResponse(
        "partials/posture_snapshots_panel.html",
        {
            "request": request,
            "investigation_id": investigation_id,
            "snapshots": snapshots,
            "kind_labels": POSTURE_KIND_LABELS,
        },
    )


@router.get(
    "/investigations/{investigation_id}/posture-snapshots/compare/partial",
    response_class=HTMLResponse,
)
async def posture_compare_partial(
    investigation_id: str,
    request: Request,
    before: str,
    after: str,
):
    from apps.investigation_core.defensive.services.posture_service import (
        PostureSnapshotService,
    )

    async with get_db() as db:
        svc = PostureSnapshotService(db)
        comparison = await svc.compare(before, after)
    if comparison is None:
        raise HTTPException(status_code=404, detail="Snapshot(s) not found")

    return templates.TemplateResponse(
        "partials/posture_comparison_panel.html",
        {
            "request": request,
            "investigation_id": investigation_id,
            "comparison": comparison,
        },
    )


# ── Cross-investigation comparison (Phase 15) ─────────────────────────────


@router.get(
    "/investigations/{investigation_id}/comparison/partial",
    response_class=HTMLResponse,
)
async def comparison_partial(investigation_id: str, request: Request):
    """Cross-investigation comparison — repeated themes + common remediation gaps."""
    from apps.investigation_core.intelligence.engine import (
        comparison_summary,
        themes_for_findings,
    )
    from apps.investigation_core.services.investigation_service import (
        InvestigationService,
    )
    from apps.scanner_orchestration.storage.finding_repo import (
        NormalizedFindingRepository,
    )

    async with get_db() as db:
        inv_svc = InvestigationService(db)
        inv = await inv_svc.get_by_id(investigation_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        summary = await comparison_summary(db)
        # Identify themes ACTIVE in this investigation so we can mark which
        # repeated themes also appear here
        repo = NormalizedFindingRepository(db)
        own_findings = await repo.list_for_investigation(investigation_id)
        own_themes = themes_for_findings(own_findings)
        own_theme_ids = {t.theme_id for t in own_themes}

    response = templates.TemplateResponse(
        "partials/investigation_comparison_panel.html",
        {
            "request": request,
            "investigation": inv,
            "investigation_id": investigation_id,
            "summary": summary,
            "own_theme_ids": own_theme_ids,
        },
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


# ── Evidence backfill — maintenance endpoint ───────────────────────────────


@router.post("/investigations/{investigation_id}/backfill-evidence-refs")
async def backfill_evidence_refs(
    investigation_id: str,
    dry_run: bool = False,
    x_maintenance_key: str | None = Header(default=None),
):
    """Back-fill evidence_refs for findings persisted before the Phase 5 ordering fix.

    Matches artifacts by exact title: "[SCANNER] finding.title"
    Capability: maintenance — requires X-Maintenance-Key header when
    MAINTENANCE_API_KEY environment variable is configured.
    """
    _check_maintenance_key(x_maintenance_key)

    from apps.investigation_core.evidence.storage.artifact_repo import ArtifactRepository
    from apps.scanner_orchestration.storage.finding_repo import NormalizedFindingRepository

    async with get_db() as db:
        finding_repo = NormalizedFindingRepository(db)
        art_repo = ArtifactRepository(db)

        findings = await finding_repo.list_with_empty_evidence_refs(investigation_id)
        all_artifacts = await art_repo.list_for_investigation(investigation_id)

        by_title: dict[str, list[str]] = {}
        for art in all_artifacts:
            by_title.setdefault(art.title, []).append(art.evidence_id)

        repaired = skipped_ambiguous = skipped_not_found = 0
        for finding in findings:
            expected = f"[{finding.source_scanner.upper()}] {finding.title}"
            matches = by_title.get(expected, [])
            if len(matches) == 1:
                if not dry_run:
                    await finding_repo.update_evidence_refs(finding.finding_id, matches)
                repaired += 1
            elif len(matches) == 0:
                skipped_not_found += 1
            else:
                skipped_ambiguous += 1

    return {
        "dry_run": dry_run,
        "candidates": len(findings),
        "repaired": repaired,
        "skipped_not_found": skipped_not_found,
        "skipped_ambiguous": skipped_ambiguous,
        "note": "Re-run without ?dry_run=true to apply." if dry_run else "Complete.",
    }


# ── Bundle 3 — Autonomous Solve Loop routes ──────────────────────────────────


@router.post(
    "/investigations/{investigation_id}/autonomous/start",
    response_class=HTMLResponse,
)
async def autonomous_start(
    investigation_id: str,
    request: Request,
    finding_id: str = "",
):
    """Start an autonomous solve run for an investigation.

    OPT-IN mode. The operator confirms once; the loop runs without per-step approval.
    Returns the progress partial (polls every 5s via htmx).
    """
    from apps.conductor.autonomous_orchestrator import (
        AutonomousBudget, is_running, start_autonomous_task,
    )
    from apps.conductor.investigation_state import load_state_async, save_state_async
    from apps.investigation_core.services.investigation_service import InvestigationService

    if is_running(investigation_id):
        return HTMLResponse(
            content='<div class="text-amber-700 text-xs py-2">Autonomous run already in progress.</div>'
        )

    async with get_db() as db:
        inv = await InvestigationService(db).get_by_id(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    target = inv.targets[0] if inv.targets else ""

    # Clear stop flag + reset status
    state = await load_state_async(investigation_id)
    state.autonomous_stop_requested = False
    state.autonomous_status = "starting"
    state.autonomous_run_log = []
    await save_state_async(state)

    # Phase 3: whole-tree traversal — discover ALL findings, not one biased pick.
    # The orchestrator will work every applicable branch across every finding.
    # finding_ids=None tells run_autonomous to auto-discover all investigation findings.
    # Sanity check: ensure at least one finding exists before starting.
    has_findings = False
    try:
        async with get_db() as db:
            from apps.scanner_orchestration.storage.finding_repo import NormalizedFindingRepository
            all_finds = await NormalizedFindingRepository(db).list_for_investigation(investigation_id)
            has_findings = bool(all_finds)
    except Exception:
        pass

    if not has_findings:
        return HTMLResponse(
            content='<div class="text-red-400 text-xs py-2">No findings to target — run recon first.</div>'
        )

    budget = AutonomousBudget()
    start_autonomous_task(investigation_id, finding_id="", target=target, budget=budget,
                          finding_ids=None)

    _poll_url = (
        f"/api/v1/validation/workspace/investigations/{investigation_id}/autonomous/status"
    )
    content = (
        f'<div id="autonomous-progress-{investigation_id}" '
        f'hx-get="{_poll_url}" hx-trigger="every 5s" hx-swap="outerHTML">'
        f'<div class="text-xs text-zinc-400 py-1">Autonomous run starting…</div>'
        f'</div>'
    )
    return HTMLResponse(content=content)


@router.post(
    "/investigations/{investigation_id}/autonomous/stop",
)
async def autonomous_stop(investigation_id: str):
    """Request the autonomous loop to stop before its next dispatch."""
    from apps.conductor.autonomous_orchestrator import request_stop
    await request_stop(investigation_id)
    return {"status": "stop_requested"}


@router.post(
    "/investigations/{investigation_id}/autonomous/seed",
    response_class=HTMLResponse,
)
async def autonomous_seed(investigation_id: str, request: Request):
    """Layer 2 operator-seeded autonomous start.

    The operator clicks a technique (or several) in the mindmap; this route
    receives the selection, seeds the first work order(s) with the chosen
    engine(s), and starts the autonomous loop. Step 1 = operator's choice.
    Steps 2+ = AI-composed continuation.

    Body (JSON): {finding_id: str, selections: [{engine_id, concept_id, title}, ...]}
    Single selection → one seeded branch. Multiple → bounded concurrent batch.
    """
    from apps.conductor.autonomous_orchestrator import (
        AutonomousBudget, is_running, start_autonomous_task,
    )
    from apps.conductor.investigation_state import load_state_async, save_state_async
    from apps.investigation_core.services.investigation_service import InvestigationService

    try:
        body = await request.json()
    except Exception:
        return HTMLResponse(
            content='<div class="text-red-400 text-xs py-2">Invalid request body (expected JSON).</div>'
        )

    finding_id: str = body.get("finding_id", "")
    selections: list = body.get("selections", [])
    seed_op_params: dict = dict(body.get("operator_params") or {})  # incl. self_pass when present

    if not finding_id or not selections:
        return HTMLResponse(
            content='<div class="text-red-400 text-xs py-2">finding_id and selections required.</div>'
        )

    if is_running(investigation_id):
        return HTMLResponse(
            content='<div class="text-amber-700 text-xs py-2">Autonomous run already in progress — stop it first.</div>'
        )

    async with get_db() as db:
        inv = await InvestigationService(db).get_by_id(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    target = inv.targets[0] if inv.targets else ""

    # Build seeded batch from operator selections.
    # Each entry {engine_id, primitive_id, concept_id, params, rationale, finding_id}
    # finding_id is per-selection (supports whole-tree seeding where each selection may
    # target a different finding). Falls back to the request-level finding_id if absent.
    seeded_batch: list[dict] = []
    for sel in selections:
        eid = sel.get("engine_id", "")
        if not eid:
            continue
        cid = sel.get("concept_id", "")
        params: dict = {"concept_id": cid} if cid else {}
        if sel.get("oracle_strategy"):
            params["oracle_strategy"] = sel["oracle_strategy"]
        sel_fid = sel.get("finding_id") or finding_id  # per-selection or request-level
        seeded_batch.append({
            "engine_id":    eid,
            "primitive_id": eid,
            "concept_id":   cid,
            "params":       params,
            "finding_id":   sel_fid,
            "rationale":    f"Operator selected: {sel.get('title', eid)}",
        })

    if not seeded_batch:
        return HTMLResponse(
            content='<div class="text-red-400 text-xs py-2">No valid engine selections.</div>'
        )

    # Clear stop flag; mark starting
    state = await load_state_async(investigation_id)
    state.autonomous_stop_requested = False
    state.autonomous_status = "starting"
    state.autonomous_run_log = []
    await save_state_async(state)

    # Budget: max_parallel=1 (ordered execution: priority branch first, then remaining);
    # max_attempts scales with seed count so oracle progression fits for all branches.
    n_seeds = len(seeded_batch)
    budget = AutonomousBudget(
        max_parallel = 1,
        max_attempts = max(16, n_seeds * 4),
    )
    start_autonomous_task(
        investigation_id, finding_id, target, budget,
        seeded_batch=seeded_batch,
        operator_params=seed_op_params,   # threads self_pass etc. to planner iterations
    )

    _poll_url = (
        f"/api/v1/validation/workspace/investigations/{investigation_id}/autonomous/status"
    )
    content = (
        f'<div id="autonomous-progress-{investigation_id}" '
        f'hx-get="{_poll_url}" hx-trigger="every 5s" hx-swap="outerHTML">'
        f'<div class="text-xs text-zinc-400 py-1">'
        f'AI continuation starting from {len(seeded_batch)} operator selection(s)…'
        f'</div>'
        f'</div>'
    )
    return HTMLResponse(content=content)


@router.get(
    "/investigations/{investigation_id}/autonomous/status",
    response_class=HTMLResponse,
)
async def autonomous_status(investigation_id: str, request: Request):
    """Progress poll endpoint. Returns HTML partial for htmx swap.

    When running: shows walk history + stop button, continues polling.
    When stopped: shows final outcome, stops polling.
    """
    from apps.conductor.autonomous_orchestrator import get_status, is_running

    data = await get_status(investigation_id)
    status    = data.get("status", "idle")
    run_log   = data.get("run_log", [])
    running   = is_running(investigation_id) or status == "running"

    _poll_url = (
        f"/api/v1/validation/workspace/investigations/{investigation_id}/autonomous/status"
    )
    _stop_url = (
        f"/api/v1/validation/workspace/investigations/{investigation_id}/autonomous/stop"
    )

    # ── Build rows from walk history ──────────────────────────────────────────
    rows_html = ""
    for entry in run_log:
        attempt     = entry.get("attempt", "?")
        prim        = entry.get("primitive_id", "?")
        rationale   = entry.get("rationale", "")[:60]
        res_state   = entry.get("result_state", "")
        res_summary = entry.get("result_summary", "")[:80]
        solved_flag = entry.get("solved", False)
        # Phase 1 decision trail: show AI vs operator source
        source      = entry.get("source", "ai")
        source_tag  = (
            '<span class="text-[9px] text-[#0969da] font-semibold">[AI]</span> '
            if source == "ai" else
            '<span class="text-[9px] text-[#bf8700] font-semibold">[Op]</span> '
        )

        state_badge = {
            "succeeded": '<span class="text-emerald-600 font-medium">✓ success</span>',
            "exhausted":  '<span class="text-amber-600">⊘ exhausted</span>',
            "failed":     '<span class="text-red-500">✕ failed</span>',
            "running":    '<span class="text-blue-500 animate-pulse">▸ running</span>',
            "timeout":    '<span class="text-zinc-400">⏱ timeout</span>',
            "error":      '<span class="text-red-600">! error</span>',
        }.get(res_state, f'<span class="text-zinc-400">{res_state}</span>')

        solved_tag = ' <span class="text-emerald-600 font-bold">★ SOLVED</span>' if solved_flag else ""

        rows_html += (
            f'<tr class="border-t border-[#e8eaed]">'
            f'<td class="px-2 py-1 text-zinc-500 shrink-0">{attempt}</td>'
            f'<td class="px-2 py-1 font-mono text-[10px] text-[#0969da]">{source_tag}{prim}</td>'
            f'<td class="px-2 py-1 text-zinc-500 text-[10px]">{rationale}</td>'
            f'<td class="px-2 py-1">{state_badge}{solved_tag}</td>'
            f'<td class="px-2 py-1 text-zinc-400 text-[10px]">{res_summary}</td>'
            f'</tr>'
        )

    # ── Status banner ─────────────────────────────────────────────────────────
    status_labels = {
        "solved":           ("✓ Solved", "text-emerald-600"),
        "budget":           ("⏹ Budget reached", "text-amber-700"),
        "no_progress":      ("⏹ No progress", "text-amber-700"),
        "no_path":          ("⏹ No path", "text-zinc-500"),
        "no_path:repeat":   ("⏹ No new path", "text-zinc-500"),
        "operator_stopped": ("⏹ Stopped by operator", "text-zinc-500"),
        "error":            ("✕ Error", "text-red-600"),
        "running":          ("▸ Running…", "text-blue-600"),
        "starting":         ("▸ Starting…", "text-blue-600"),
        "idle":             ("Idle", "text-zinc-400"),
    }
    label_text, label_cls = status_labels.get(status, (status, "text-zinc-400"))

    stop_button = ""
    if running:
        stop_button = (
            f'<button hx-post="{_stop_url}" hx-swap="none" '
            f'class="ml-2 px-2 py-0.5 text-[10px] text-white bg-red-500 hover:bg-red-400 rounded">'
            f'Stop</button>'
        )

    hx_attrs = ""
    if running:
        hx_attrs = f'hx-get="{_poll_url}" hx-trigger="every 5s" hx-swap="outerHTML"'

    table_html = ""
    if rows_html:
        table_html = (
            f'<table class="w-full text-[11px] text-[#1f2328] mt-1">'
            f'<thead><tr class="text-zinc-400">'
            f'<th class="px-2 py-0.5 text-left">#</th>'
            f'<th class="px-2 py-0.5 text-left">Primitive</th>'
            f'<th class="px-2 py-0.5 text-left">Rationale</th>'
            f'<th class="px-2 py-0.5 text-left">Result</th>'
            f'<th class="px-2 py-0.5 text-left">Summary</th>'
            f'</tr></thead>'
            f'<tbody>{rows_html}</tbody>'
            f'</table>'
        )

    content = (
        f'<div id="autonomous-progress-{investigation_id}" {hx_attrs} '
        f'class="rounded-md border border-[#d0d7de] px-3 py-2 mt-2 text-xs">'
        f'<div class="flex items-center gap-2 mb-1">'
        f'<span class="font-medium {label_cls}">{label_text}</span>'
        f'<span class="text-zinc-400 text-[10px]">Attempts: {len(run_log)}</span>'
        f'{stop_button}'
        f'</div>'
        f'{table_html}'
        f'</div>'
    )
    return HTMLResponse(content=content)


# ── Phase D — Unknown Artifact batch review ───────────────────────────────────

@router.get("/unknowns")
async def list_unknown_artifacts(
    status: str = "pending_review",
    limit:  int = 50,
):
    """List Unknown Artifacts across all investigations.

    Defaults to pending_review; use status=resolved|ignored for other buckets.
    Returns JSON list of artifact dicts.
    """
    from apps.conductor.unknown_store import list_unknowns_async
    items = await list_unknowns_async(status=status or None, limit=limit)
    return {"status": status, "count": len(items), "items": items}


@router.post("/unknowns/{artifact_id}/status")
async def update_unknown_artifact_status(
    artifact_id: str,
    status:      str,
    resolution:  str = "",
):
    """Mark an Unknown Artifact as resolved or ignored.

    status: resolved | ignored
    resolution: optional free text (e.g. 'added concept-new-attack.md')
    """
    from apps.conductor.unknown_store import update_unknown_status_async
    ok = await update_unknown_status_async(
        artifact_id = artifact_id,
        status      = status,
        resolution  = resolution or None,
    )
    return {"ok": ok, "id": artifact_id, "status": status}


@router.get("/unknowns/count")
async def unknown_artifacts_count():
    """Cross-investigation pending-unknown count for the left-panel unknowns banner.

    Returns: {"count": N}   — N is the number of pending_review artifacts across all
    investigations.  Used by the left-panel banner to determine whether to display.
    """
    from apps.conductor.unknown_store import count_pending_async
    count = await count_pending_async()
    return {"count": count}


# ── Phase E — Planner controller endpoint ─────────────────────────────────────

@router.post("/investigations/{investigation_id}/planner/run")
async def planner_run(
    investigation_id: str,
    max_iterations: int = 1,
    operator_params: "dict | None" = None,
):
    """Phase E — Run one or more planner iterations for this investigation.

    Bug 1 fix: operator_params threads engine-specific configuration through the
    planner path (previously params={} was hardcoded, preventing parameterized
    engines like credential_brute_counter_reset from being configured).

    operator_params examples:
      {"self_pass": "peter"}    # counter-reset: password for the provided self-login
      {"reset_every": 2}        # counter-reset: interleave frequency

    Params NOT needed here (sourced automatically from STATE.goal):
      self_user   ← goal.provided_self_user
      target_user ← goal.target_user

    max_iterations: 1 = single step (safe); higher = run multiple steps.
    Returns: {action, reason, iterations, results, agent_state_summary}
    """
    from apps.conductor.autonomous_orchestrator import run_planner_loop
    from apps.conductor.agent_state import (
        get_or_init_agent_state_async,
        load_agent_state_async,
    )
    from apps.investigation_workspace.bootstrap.runtime import get_run

    # Resolve target from bootstrap run
    brun = get_run(investigation_id)
    target = getattr(brun, "target", "") if brun else ""
    if not target:
        # Fallback: try to get target from request context via investigation record
        try:
            from apps.validation.database import get_db
            async with get_db() as db:
                cur = await db.execute(
                    "SELECT target FROM investigations WHERE investigation_id=? LIMIT 1",
                    (investigation_id,),
                )
                row = await cur.fetchone()
                target = str(row[0]) if row and row[0] else ""
        except Exception:
            pass

    # Ensure agent_state is initialized
    await get_or_init_agent_state_async(investigation_id, target=target)

    # Fix 1 — Set provided_self_user / target_user at OBJECTIVE level so ALL subsequent
    # engine captures can be classified (not just the counter-reset path which was the
    # only previous setter).  Accepts them via operator_params so there are no hardcoded
    # literals; the objective context comes from the operator at investigation start.
    _op = dict(operator_params or {})
    _provided_self = _op.get("provided_self_user")
    _target_user   = _op.get("target_user")
    if _provided_self or _target_user:
        try:
            from apps.conductor.agent_state import _get_state_lock, save_agent_state_async
            _f1_lock = _get_state_lock(investigation_id)
            async with _f1_lock:
                _f1_state = await load_agent_state_async(investigation_id)
                if _f1_state and "goal" in _f1_state:
                    if _provided_self:
                        _f1_state["goal"]["provided_self_user"] = _provided_self
                    if _target_user:
                        _f1_state["goal"]["target_user"] = _target_user
                    await save_agent_state_async(investigation_id, _f1_state)
        except Exception:
            pass   # non-fatal — state update failed but planner can still run

    # Run the planner loop — operator_params threaded through (Bug 1 fix)
    result = await run_planner_loop(
        investigation_id = investigation_id,
        target           = target,
        max_iterations   = max(1, min(max_iterations, 20)),
        operator_params  = dict(operator_params or {}),
    )

    # Append final state summary
    agent_state = await load_agent_state_async(investigation_id)
    result["agent_state_summary"] = {
        "solved":           agent_state.get("solved", False),
        "facts_count":      len(agent_state.get("facts", [])),
        "artifacts_count":  sum(
            len(v) for v in (agent_state.get("artifacts") or {}).values()
        ),
        "pending_count":    len(agent_state.get("pending", [])),
        "completed_count":  len(agent_state.get("completed", [])),
        "planner_log_len":  len(agent_state.get("planner_log", [])),
    }
    return result


# ── Part 3 — Chat history persistence ────────────────────────────────────────

@router.get("/investigations/{investigation_id}/chat")
async def get_chat_history(investigation_id: str, limit: int = 500):
    """Load persisted Zone C chat history for an investigation (ordered oldest-first).

    Returns: [{id, role, content, created_at}]
    """
    from apps.validation.database import get_db
    async with get_db() as db:
        cur = await db.execute(
            """SELECT id, role, content, created_at
               FROM investigation_chat_history
               WHERE investigation_id=?
               ORDER BY created_at ASC
               LIMIT ?""",
            (investigation_id, limit),
        )
        rows = await cur.fetchall()
    return [{"id": r[0], "role": r[1], "content": r[2], "created_at": r[3]} for r in rows]


@router.post("/investigations/{investigation_id}/chat")
async def append_chat_message(
    investigation_id: str,
    role: str,
    content: str,
):
    """Persist one Zone C chat message for an investigation.

    role: "user" | "assistant"
    content: the message text (truncated at 10 000 chars to prevent abuse).
    Returns: {"id": <uuid>}
    """
    import uuid as _uuid
    from datetime import datetime, timezone
    from apps.validation.database import get_db

    msg_id = str(_uuid.uuid4())
    now    = datetime.now(timezone.utc).isoformat()
    text   = str(content or "")[:10_000]
    r_val  = str(role or "assistant")[:20]

    async with get_db() as db:
        await db.execute(
            """INSERT OR IGNORE INTO investigation_chat_history
               (id, investigation_id, role, content, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (msg_id, investigation_id, r_val, text, now),
        )
        await db.commit()
    return {"id": msg_id}
