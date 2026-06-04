"""Metasploit page router.

This router is intentionally isolated from the rest of the validation
pipeline. None of the scanner / correlator / executor / queue / findings
code imports anything from here, and this module does not write into any
of those tables. Every Metasploit invocation is a deliberate user action
in the dedicated Metasploit tab.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from apps.validation.database import get_db
from apps.validation.models import MsfRun, MsfRunMode, MsfRunStatus
from apps.validation.repositories import MsfRunRepository
from apps.validation.services.metasploit import (
    MsfNotConfigured,
    MsfNotReachable,
    get_msf_client,
)
from apps.validation.services.msf_recipes import (
    get_recipe,
    grouped_modules,
    list_services,
)
from apps.validation.services.msf_wordlists import (
    USER_OPTION_NAMES,
    PASS_OPTION_NAMES,
    USERPASS_OPTION_NAMES,
    WORDLIST_OPTION_NAMES,
    list_wordlists,
)
from sdk import Logger

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/metasploit", response_class=HTMLResponse)
async def metasploit_page(request: Request):
    async with get_db() as db:
        runs = await MsfRunRepository(db).list_recent(limit=20)
    return templates.TemplateResponse(
        "metasploit.html",
        {
            "request": request,
            "active": "metasploit",
            "runs": runs,
            "guide_services": list_services(),
            "wordlists": list_wordlists(),
            "wordlist_option_categories": {
                "user": sorted(USER_OPTION_NAMES),
                "password": sorted(PASS_OPTION_NAMES),
                "userpass": sorted(USERPASS_OPTION_NAMES),
            },
            "wordlist_option_names": WORDLIST_OPTION_NAMES,
        },
    )


@router.get("/metasploit/guide/{service_key}", response_class=HTMLResponse)
async def metasploit_guide(request: Request, service_key: str):
    recipe = get_recipe(service_key)
    if recipe is None:
        return HTMLResponse(
            f"<p class='text-muted mono' style='font-size:12px;'>"
            f"No guide for '{service_key}' yet.</p>",
            status_code=200,
        )
    return templates.TemplateResponse(
        "partials/msf_guide.html",
        {
            "request": request,
            "service_key": service_key,
            "recipe": recipe,
            "groups": grouped_modules(recipe),
        },
    )


@router.get("/metasploit/status")
async def metasploit_status() -> dict:
    return await get_msf_client().status()


@router.get("/metasploit/modules/search", response_class=HTMLResponse)
async def metasploit_search(
    request: Request,
    q: str = "",
    module_type: str | None = None,
    limit: int = 100,
):
    try:
        results = await get_msf_client().search(
            query=q, module_type=module_type, limit=limit
        )
    except (MsfNotConfigured, MsfNotReachable) as e:
        return HTMLResponse(
            f"<p class='text-muted mono' style='font-size:12px;'>"
            f"Metasploit RPC unreachable: {e}</p>",
            status_code=200,
        )
    return templates.TemplateResponse(
        "partials/msf_search_results.html",
        {"request": request, "results": results, "query": q},
    )


@router.get("/metasploit/modules/info", response_class=HTMLResponse)
async def metasploit_module_info(
    request: Request,
    module_type: str,
    module_path: str,
):
    try:
        info = await get_msf_client().module_info(module_type, module_path)
    except (MsfNotConfigured, MsfNotReachable) as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    return templates.TemplateResponse(
        "partials/msf_module_info.html",
        {
            "request": request,
            "m": info,
            "wordlist_option_names": WORDLIST_OPTION_NAMES,
        },
    )


class MsfRunRequest(BaseModel):
    module_type: str
    module_path: str
    mode: str = "run"
    options: dict[str, str | int | float | bool | None] = {}
    timeout_s: int = 300


@router.post("/metasploit/run", response_class=HTMLResponse)
async def metasploit_run(request: Request, payload: MsfRunRequest):
    if payload.mode not in ("run", "check"):
        raise HTTPException(status_code=400, detail="mode must be 'run' or 'check'")
    if not payload.module_path or not payload.module_type:
        raise HTTPException(status_code=400, detail="module_type and module_path are required")

    target = str(payload.options.get("RHOSTS") or payload.options.get("RHOST") or "")

    # Persist a pending row first so the UI can show it immediately.
    run = MsfRun(
        module_path=payload.module_path,
        module_type=payload.module_type,
        options={k: v for k, v in (payload.options or {}).items() if v not in (None, "")},
        target=target or None,
        mode=MsfRunMode(payload.mode),
        status=MsfRunStatus.RUNNING,
    )
    async with get_db() as db:
        await MsfRunRepository(db).insert(run)

    Logger.info(
        "msf.run.start",
        extra={
            "id": run.id,
            "module": f"{payload.module_type}/{payload.module_path}",
            "mode": payload.mode,
            "target": target,
        },
    )

    output = ""
    status = MsfRunStatus.COMPLETED
    try:
        output = await get_msf_client().run_via_console(
            module_type=payload.module_type,
            module_path=payload.module_path,
            options=run.options,
            mode=payload.mode,
            timeout_s=max(10, min(payload.timeout_s, 1800)),
        )
    except TimeoutError as e:
        status = MsfRunStatus.TIMED_OUT
        output = str(e)
    except (MsfNotConfigured, MsfNotReachable) as e:
        status = MsfRunStatus.FAILED
        output = f"Metasploit RPC error: {e}"
    except Exception as e:  # noqa: BLE001
        status = MsfRunStatus.FAILED
        output = f"Unhandled error: {e}"

    async with get_db() as db:
        repo = MsfRunRepository(db)
        await repo.update_completion(run.id, status, output)
        fresh = await repo.get_by_id(run.id)

    Logger.info(
        "msf.run.complete",
        extra={
            "id": run.id,
            "module": f"{payload.module_type}/{payload.module_path}",
            "status": str(status),
            "output_chars": len(output or ""),
        },
    )

    return templates.TemplateResponse(
        "partials/msf_run_output.html",
        {"request": request, "run": fresh},
    )


@router.get("/metasploit/runs/{run_id}", response_class=HTMLResponse)
async def metasploit_run_detail(request: Request, run_id: str):
    async with get_db() as db:
        run = await MsfRunRepository(db).get_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return templates.TemplateResponse(
        "partials/msf_run_output.html",
        {"request": request, "run": run},
    )


@router.delete("/metasploit/runs/{run_id}", response_class=HTMLResponse)
async def metasploit_run_delete(run_id: str):
    async with get_db() as db:
        await MsfRunRepository(db).delete(run_id)
    return HTMLResponse(content="", status_code=200)
