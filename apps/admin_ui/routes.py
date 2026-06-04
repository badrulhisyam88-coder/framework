"""Admin UI router — mounted at /admin/* in the main FastAPI app.

No authentication (single-operator local tool).
Panels: Dashboard (settings), Conductor, Execution Orchestrator, Enum Gaps.
Conductor and Execution poll every 2s via htmx hx-trigger="every 2s".
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from apps.admin_ui.state_provider import (
    get_conductor,
    get_conductor_panel_data,
    get_execution_panel_data,
)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter(prefix="/admin", tags=["admin"])

# Module-level last-rebuild timestamp (no DB needed per spec).
_vault_last_rebuild: str | None = None


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%H:%M:%S UTC")


@router.get("", include_in_schema=False)
async def admin_root():
    return RedirectResponse(url="/admin/settings", status_code=302)


@router.get("/conductor", response_class=HTMLResponse)
async def conductor_panel(request: Request):
    conductor = get_conductor()
    data = await get_conductor_panel_data(conductor)
    return templates.TemplateResponse(
        request,
        "admin/conductor_panel.html",
        {**data, "now_iso": _now_iso()},
    )


@router.get("/conductor/refresh", response_class=HTMLResponse)
async def conductor_refresh(request: Request):
    conductor = get_conductor()
    data = await get_conductor_panel_data(conductor)
    return templates.TemplateResponse(
        request,
        "admin/_conductor_table.html",
        {**data, "now_iso": _now_iso()},
    )


@router.get("/execution", response_class=HTMLResponse)
async def execution_panel(request: Request):
    conductor = get_conductor()
    data = await get_execution_panel_data(conductor)
    return templates.TemplateResponse(
        request,
        "admin/execution_panel.html",
        {**data, "now_iso": _now_iso()},
    )


@router.get("/execution/refresh", response_class=HTMLResponse)
async def execution_refresh(request: Request):
    conductor = get_conductor()
    data = await get_execution_panel_data(conductor)
    return templates.TemplateResponse(
        request,
        "admin/_execution_table.html",
        {**data, "now_iso": _now_iso()},
    )


def _gate_context() -> dict:
    from apps.conductor.gates import list_gates
    return {"gates": list_gates(), "now_iso": _now_iso()}


def _dashboard_context(save_ok: bool | None = None, save_error: str | None = None) -> dict:
    from apps.admin_ui.model_settings import EMBED_MODELS, LLM_MODELS, load
    from apps.conductor.gates import list_gates
    cfg = load()
    ctx: dict = {
        "gates": list_gates(),
        "llm_models": LLM_MODELS,
        "embed_models": EMBED_MODELS,
        "current_llm": cfg["llm_model"],
        "current_embed": cfg["embed_model"],
        "now_iso": _now_iso(),
    }
    if save_ok is True:
        ctx["save_ok"] = True
    if save_error is not None:
        ctx["save_error"] = save_error
    return ctx


@router.get("/settings", response_class=HTMLResponse)
async def settings_panel(request: Request):
    return templates.TemplateResponse(
        request,
        "admin/settings_panel.html",
        _dashboard_context(),
    )


@router.get("/settings/refresh", response_class=HTMLResponse)
async def settings_refresh(request: Request):
    return templates.TemplateResponse(
        request,
        "admin/_settings_table.html",
        _gate_context(),
    )


@router.post("/settings/{gate_id}", response_class=HTMLResponse)
async def toggle_gate(gate_id: str, request: Request):
    from apps.conductor.gates import get_gate, set_gate
    try:
        current = get_gate(gate_id)
        set_gate(gate_id, not current)
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Unknown gate: {gate_id!r}") from None
    return templates.TemplateResponse(
        request,
        "admin/_settings_table.html",
        _gate_context(),
    )


@router.post("/session-auth/refresh", response_class=HTMLResponse)
async def refresh_session_auth(request: Request):
    """Operator-driven session refresh. Body: {target_base: str, auth: dict}.

    Clears the expired flag and stores the new auth. No automatic re-auth —
    operator provides credentials explicitly per V2 decision 6.
    """
    body = await request.json()
    target_base = body.get("target_base", "").strip()
    auth = body.get("auth", {})
    if not target_base:
        raise HTTPException(status_code=400, detail="target_base is required")
    conductor = get_conductor()
    conductor.refresh_target_auth(target_base, auth)
    data = await get_conductor_panel_data(conductor)
    return templates.TemplateResponse(
        request,
        "admin/_conductor_table.html",
        {**data, "now_iso": _now_iso()},
    )


@router.post("/exploitation/complete", response_class=HTMLResponse)
async def exploitation_complete(request: Request):
    """Operator-driven exploitation phase completion. Body: {investigation_id: str}.

    Marks the exploitation phase done for the specified investigation.
    Per clarification C3: completion is operator-driven; no auto-complete path.
    Returns 404 if the investigation is not active or not in exploitation phase.
    """
    body = await request.json()
    investigation_id = body.get("investigation_id", "").strip()
    if not investigation_id:
        raise HTTPException(status_code=400, detail="investigation_id is required")
    conductor = get_conductor()
    delivered = await conductor.operator_complete_exploitation(investigation_id)
    if not delivered:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation {investigation_id!r} not active or not in exploitation phase",
        )
    data = await get_conductor_panel_data(conductor)
    return templates.TemplateResponse(
        request,
        "admin/_conductor_table.html",
        {**data, "now_iso": _now_iso()},
    )


@router.get("/enumeration-gaps", response_class=HTMLResponse)
async def enumeration_gaps_panel(request: Request):
    gaps: list[dict] = []
    try:
        from apps.validation.database import get_db
        from apps.scanner_orchestration.storage.finding_repo import NormalizedFindingRepository
        async with get_db() as db:
            gaps = await NormalizedFindingRepository(db).list_enumeration_gaps()
    except Exception:
        pass
    return templates.TemplateResponse(
        request,
        "admin/enumeration_gaps_panel.html",
        {"gaps": gaps, "now_iso": _now_iso()},
    )


def _model_settings_context(save_ok: bool | None = None, save_error: str | None = None) -> dict:
    from apps.admin_ui.model_settings import EMBED_MODELS, LLM_MODELS, load
    cfg = load()
    ctx: dict = {
        "llm_models": LLM_MODELS,
        "embed_models": EMBED_MODELS,
        "current_llm": cfg["llm_model"],
        "current_embed": cfg["embed_model"],
        "now_iso": _now_iso(),
    }
    if save_ok is True:
        ctx["save_ok"] = True
    if save_error is not None:
        ctx["save_error"] = save_error
    return ctx


@router.get("/settings/models", response_class=HTMLResponse)
async def model_settings_get(request: Request):
    return templates.TemplateResponse(
        request,
        "admin/_model_settings_form.html",
        _model_settings_context(),
    )


@router.post("/settings/models", response_class=HTMLResponse)
async def model_settings_post(request: Request):
    form = await request.form()
    llm_model = str(form.get("llm_model", "")).strip()
    embed_model = str(form.get("embed_model", "")).strip()
    try:
        from apps.admin_ui.model_settings import save
        save(llm_model=llm_model, embed_model=embed_model)
        return templates.TemplateResponse(
            request,
            "admin/_model_settings_form.html",
            _model_settings_context(save_ok=True),
        )
    except ValueError as exc:
        return templates.TemplateResponse(
            request,
            "admin/_model_settings_form.html",
            _model_settings_context(save_error=str(exc)),
        )


@router.post("/vault/rebuild", response_class=JSONResponse)
async def vault_rebuild():
    """Force re-index of all vault files into ChromaDB.

    Safe to call at any time; no-op if vault not mounted or chromadb unavailable.
    Returns {"status": "ok", "indexed": N}.
    """
    global _vault_last_rebuild
    from apps.conductor.qwen.vault_embedder import rebuild_index
    count = await rebuild_index()
    _vault_last_rebuild = datetime.now(UTC).isoformat()
    return JSONResponse(content={"status": "ok", "indexed": count})


@router.get("/vault/status", response_class=JSONResponse)
async def vault_status():
    """Return ChromaDB entry count and last rebuild timestamp.

    Returns {"count": N, "last_rebuild": "ISO timestamp or never"}.
    count=0 if ChromaDB is unavailable.
    """
    count = 0
    try:
        from apps.conductor.qwen.vault_embedder import get_entry_count
        count = await get_entry_count()
    except Exception:
        pass
    return JSONResponse(content={
        "count": count,
        "last_rebuild": _vault_last_rebuild or "never",
    })


@router.get("/qwen/ping", response_class=JSONResponse)
async def qwen_ping():
    """Confirm AI/Ollama is reachable from inside the container.

    Always returns HTTP 200. Check the 'status' field for health:
      - "ok"          — reachable and model present
      - "unavailable" — unreachable or model missing (see 'error')
    """
    from apps.conductor.qwen.client import ping_details
    result = await ping_details()
    return JSONResponse(content=result)


@router.get("/ai/ping", response_class=JSONResponse)
async def ai_ping():
    """Alias for /admin/qwen/ping — preferred route name."""
    from apps.conductor.qwen.client import ping_details
    result = await ping_details()
    return JSONResponse(content=result)


# ── Vault ID cleanup (admin tool — explicit deletion by ID list) ─────────────

@router.post("/vault/delete-ids", response_class=JSONResponse)
async def vault_delete_ids(request: Request):
    """Delete specific document IDs from ChromaDB by exact ID list.

    Body: {"ids": ["id1", "id2", ...]}
    Returns {"deleted": N, "not_found": [...], "errors": [...]}.
    Admin-only. Use for removing stale/duplicate entries that cannot
    be removed via the general dedup algorithm.
    """
    body = await request.json()
    ids_to_delete: list[str] = body.get("ids", [])
    if not ids_to_delete:
        return JSONResponse(content={"deleted": 0, "not_found": [], "errors": ["no ids provided"]})
    deleted: list[str] = []
    not_found: list[str] = []
    errors: list[str] = []
    try:
        from apps.conductor.qwen.vault_embedder import _get_chroma_collection, _check_chromadb
        if not _check_chromadb():
            return JSONResponse(content={"deleted": 0, "not_found": [], "errors": ["chromadb unavailable"]})
        _, collection = _get_chroma_collection()
        for doc_id in ids_to_delete:
            try:
                existing = collection.get(ids=[doc_id], include=[])
                if not (existing.get("ids") or []):
                    not_found.append(doc_id)
                    continue
                collection.delete(ids=[doc_id])
                deleted.append(doc_id)
            except Exception as exc:
                errors.append(f"{doc_id}: {exc}")
    except Exception as exc:
        errors.append(str(exc))
    return JSONResponse(content={"deleted": len(deleted), "removed_ids": deleted,
                                 "not_found": not_found, "errors": errors})


# ── Vault Inspection Panel ────────────────────────────────────────────────────

_BUG_LEDGER = Path(__file__).parent.parent.parent / "docs" / "bug-ledger.md"


@router.get("/vault-inspect", response_class=HTMLResponse)
async def vault_inspect_get(request: Request):
    """Render the vault inspection + dedup admin page."""
    return templates.TemplateResponse(
        request,
        "admin/vault_inspect_panel.html",
        {"now_iso": _now_iso()},
    )


@router.post("/vault-inspect", response_class=HTMLResponse)
async def vault_inspect_post(request: Request):
    """htmx — embed query, run ChromaDB search, return results partial."""
    form = await request.form()
    finding_type = str(form.get("finding_type", "")).strip()
    description  = str(form.get("description", "")).strip()
    try:
        top_k = max(1, min(int(str(form.get("top_k", "10")) or "10"), 20))
    except (ValueError, TypeError):
        top_k = 10

    query = " ".join(filter(None, [finding_type, description]))
    results: list[dict] = []
    error: str | None = None
    unavailable = False

    if not query:
        error = "Provide at least a finding_type or description."
    else:
        try:
            from apps.conductor.qwen.vault_embedder import inspect_vault
            results = await inspect_vault(query, top_k=top_k)
            if not results:
                unavailable = True  # ChromaDB/Ollama unreachable or collection empty
        except Exception as exc:
            error = f"Vault inspection failed: {exc}"

    return templates.TemplateResponse(
        request,
        "admin/_vault_inspect_results.html",
        {
            "results":     results,
            "error":       error,
            "unavailable": unavailable,
            "query":       query,
            "top_k":       top_k,
        },
    )


@router.post("/vault-dedup", response_class=HTMLResponse)
async def vault_dedup_post(request: Request):
    """htmx — find and remove near-duplicate vault entries. Operator-triggered only."""
    from apps.conductor.qwen.vault_embedder import dedup_vault_entries
    result = await dedup_vault_entries()

    # Append removal log to bug-ledger.md
    if result.get("removed", 0) > 0:
        try:
            _BUG_LEDGER.parent.mkdir(parents=True, exist_ok=True)
            ts = _now_iso()
            lines = [f"\n## Vault dedup run — {ts}\n"]
            lines.append(f"Pairs found: {result['pairs_found']}  Removed: {result['removed']}\n")
            for entry in result.get("log", []):
                lines.append(f"- {entry}\n")
            with _BUG_LEDGER.open("a", encoding="utf-8") as fh:
                fh.writelines(lines)
        except Exception as exc:
            result.setdefault("log", []).append(f"bug-ledger write failed: {exc}")

    return templates.TemplateResponse(
        request,
        "admin/_vault_dedup_results.html",
        {"result": result, "now_iso": _now_iso()},
    )
